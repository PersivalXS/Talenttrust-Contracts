use crate::{
    amount_validation, ttl, BatchContractResult, Contract, ContractItem, ContractStatus, DataKey,
    Error, Escrow, EscrowArgs, EscrowClient, EscrowError, GovernedParameters, Milestone,
    ReleaseAuthorization, BATCH_CAP, MAX_MILESTONES,
};
use soroban_sdk::{contractimpl, symbol_short, Address, Env, Symbol, Vec};

#[contractimpl]
impl Escrow {
    /// Creates a new escrow contract with the specified client, freelancer, and milestone amounts.
    ///
    /// This is the single canonical creation path. It enforces:
    /// - Distinct client and freelancer addresses
    /// - Arbiter presence when required by the release authorization mode
    /// - Arbiter distinctness from client and freelancer
    /// - At least one milestone with all amounts strictly positive
    /// - The `MAX_MILESTONES` cap
    /// - The governed total-escrow cap (falls back to `i128::MAX` when unset)
    /// - No contract-id collision or overflow
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `client` - The address of the client funding the contract
    /// * `freelancer` - The address of the freelancer performing the work
    /// * `arbiter` - Optional arbiter address for dispute resolution
    /// * `milestones` - Vector of milestone amounts (in stroops)
    /// * `release_authorization` - Authorization mode for milestone releases
    ///
    /// # Returns
    /// The unique contract ID assigned to the new escrow.
    ///
    /// # Errors
    /// * `InvalidParticipant`   - If client and freelancer are the same address
    /// * `EmptyMilestones`      - If no milestones are provided
    /// * `InvalidMilestoneAmount` - If any milestone amount is <= 0
    /// * `MissingArbiter`       - If arbiter is required but not provided
    /// * `InvalidArbiter`       - If arbiter is same as client or freelancer
    /// * `TooManyMilestones`    - If the number of milestones exceeds `MAX_MILESTONES`
    /// * `TotalCapExceeded`     - If the sum of milestone amounts exceeds the governed cap
    /// * `ContractIdOverflow`   - If the next id would exceed `u32::MAX`
    /// * `ContractIdCollision`  - If the allocated id slot is already occupied
    pub fn create_contract(
        env: Env,
        client: Address,
        freelancer: Address,
        arbiter: Option<Address>,
        milestones: Vec<i128>,
        release_authorization: ReleaseAuthorization,
    ) -> u32 {
        Self::require_not_paused(&env);

        client.require_auth();

        if client == freelancer {
            env.panic_with_error(EscrowError::InvalidParticipant);
        }

        match release_authorization {
            ReleaseAuthorization::ArbiterOnly | ReleaseAuthorization::ClientAndArbiter
                if arbiter.is_none() =>
            {
                env.panic_with_error(EscrowError::MissingArbiter);
            }
            _ => {}
        }

        if let Some(ref arb) = arbiter {
            if arb == &client || arb == &freelancer {
                env.panic_with_error(EscrowError::InvalidArbiter);
            }
        }

        if milestones.is_empty() {
            env.panic_with_error(EscrowError::EmptyMilestones);
        }

        if milestones.len() > MAX_MILESTONES {
            env.panic_with_error(EscrowError::TooManyMilestones);
        }

        let max_total = env
            .storage()
            .persistent()
            .get::<_, GovernedParameters>(&DataKey::GovernedParameters)
            .map(|params| params.max_escrow_total_stroops)
            .unwrap_or(i128::MAX);

        let mut native_milestones = [0_i128; MAX_MILESTONES as usize];
        let len = milestones.len() as usize;
        for i in 0..len {
            native_milestones[i] = milestones.get(i as u32).unwrap();
        }
        match amount_validation::validate_milestone_amounts(&native_milestones[..len], max_total) {
            Ok(_) => (),
            Err(err) => match err {
                EscrowError::InvalidMilestoneAmount => {
                    env.panic_with_error(EscrowError::InvalidMilestoneAmount)
                }
                EscrowError::TotalCapExceeded => {
                    env.panic_with_error(EscrowError::TotalCapExceeded)
                }
                _ => env.panic_with_error(EscrowError::InvalidMilestoneAmount),
            },
        }

        ttl::extend_next_contract_id_ttl(&env);

        let id = next_contract_id(&env);

        let freelancer_addr = freelancer.clone();

        let contract = Contract {
            client: client.clone(),
            freelancer: freelancer.clone(),
            arbiter,
            status: ContractStatus::Created,
            total_deposited: 0,
            funded_amount: 0,
            released_amount: 0,
            refunded_amount: 0,
            release_authorization,
            reputation_issued: false,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Contract(id), &contract);

        let mut milestone_vec: Vec<Milestone> = Vec::new(&env);
        for amount in milestones.iter() {
            milestone_vec.push_back(Milestone {
                amount,
                funded_amount: 0,
                released: false,
                refunded: false,
                work_evidence: None,
                refunded_amount: 0,
                deadline: None,
            });
        }
        let milestone_key = Symbol::new(&env, "milestones");
        env.storage()
            .persistent()
            .set(&(DataKey::Contract(id), milestone_key), &milestone_vec);

        let next_id = id
            .checked_add(1)
            .unwrap_or_else(|| env.panic_with_error(Error::ContractIdOverflow));
        env.storage()
            .persistent()
            .set(&DataKey::NextContractId, &next_id);

        env.events().publish(
            (symbol_short!("created"), id),
            (client, freelancer_addr, env.ledger().timestamp()),
        );

        id
    }

    /// Creates multiple escrow contracts in a single call with a bounded cap.
    ///
    /// Each item in the batch is validated independently. Per-item results
    /// indicate success (with assigned contract ID) or the error code that
    /// would have been raised. The batch is rejected upfront if it exceeds
    /// [`BATCH_CAP`].
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `caller` - The address authorising the batch
    /// * `items` - Vector of contract creation requests
    ///
    /// # Returns
    /// A vector of [`BatchContractResult`], one per input item.
    ///
    /// # Errors
    /// * `BatchExceedsCap` - If `items.len() > BATCH_CAP`
    pub fn create_contracts_batch(
        env: Env,
        caller: Address,
        items: Vec<ContractItem>,
    ) -> Vec<BatchContractResult> {
        Self::require_not_paused(&env);

        caller.require_auth();

        if items.len() > BATCH_CAP {
            env.panic_with_error(EscrowError::BatchExceedsCap);
        }

        let mut results: Vec<BatchContractResult> = Vec::new(&env);

        let mut i: u32 = 0;
        while i < items.len() {
            let item = items.get(i).unwrap();
            let result = Self::try_create_contract(&env, &item, i);
            results.push_back(result);
            i += 1;
        }

        results
    }

    /// Attempt to create a single contract, returning a result instead of panicking.
    fn try_create_contract(env: &Env, item: &ContractItem, index: u32) -> BatchContractResult {
        if item.client == item.freelancer {
            return BatchContractResult {
                index,
                contract_id: None,
                error_code: Some(EscrowError::InvalidParticipant as u32),
            };
        }

        match item.release_authorization {
            ReleaseAuthorization::ArbiterOnly | ReleaseAuthorization::ClientAndArbiter
                if item.arbiter.is_none() =>
            {
                return BatchContractResult {
                    index,
                    contract_id: None,
                    error_code: Some(EscrowError::MissingArbiter as u32),
                };
            }
            _ => {}
        }

        if let Some(ref arb) = item.arbiter {
            if arb == &item.client || arb == &item.freelancer {
                return BatchContractResult {
                    index,
                    contract_id: None,
                    error_code: Some(EscrowError::InvalidArbiter as u32),
                };
            }
        }

        if item.milestones.is_empty() {
            return BatchContractResult {
                index,
                contract_id: None,
                error_code: Some(EscrowError::EmptyMilestones as u32),
            };
        }

        if item.milestones.len() > MAX_MILESTONES {
            return BatchContractResult {
                index,
                contract_id: None,
                error_code: Some(EscrowError::TooManyMilestones as u32),
            };
        }

        let max_total = env
            .storage()
            .persistent()
            .get::<_, GovernedParameters>(&DataKey::GovernedParameters)
            .map(|params| params.max_escrow_total_stroops)
            .unwrap_or(i128::MAX);

        let mut native_milestones = [0_i128; MAX_MILESTONES as usize];
        let len = item.milestones.len() as usize;
        let mut k: u32 = 0;
        while k < item.milestones.len() {
            native_milestones[k as usize] = item.milestones.get(k).unwrap();
            k += 1;
        }
        match amount_validation::validate_milestone_amounts(&native_milestones[..len], max_total) {
            Ok(_) => (),
            Err(err) => {
                let code = match err {
                    EscrowError::InvalidMilestoneAmount => EscrowError::InvalidMilestoneAmount,
                    EscrowError::TotalCapExceeded => EscrowError::TotalCapExceeded,
                    _ => EscrowError::InvalidMilestoneAmount,
                };
                return BatchContractResult {
                    index,
                    contract_id: None,
                    error_code: Some(code as u32),
                };
            }
        }

        ttl::extend_next_contract_id_ttl(env);

        let id = next_contract_id(env);

        let contract = Contract {
            client: item.client.clone(),
            freelancer: item.freelancer.clone(),
            arbiter: item.arbiter.clone(),
            status: ContractStatus::Created,
            total_deposited: 0,
            funded_amount: 0,
            released_amount: 0,
            refunded_amount: 0,
            release_authorization: item.release_authorization,
            reputation_issued: false,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Contract(id), &contract);

        let mut milestone_vec: Vec<Milestone> = Vec::new(env);
        let mut m: u32 = 0;
        while m < item.milestones.len() {
            let amount = item.milestones.get(m).unwrap();
            milestone_vec.push_back(Milestone {
                amount,
                funded_amount: 0,
                released: false,
                refunded: false,
                work_evidence: None,
                refunded_amount: 0,
                deadline: None,
            });
            m += 1;
        }
        let milestone_key = Symbol::new(env, "milestones");
        env.storage()
            .persistent()
            .set(&(DataKey::Contract(id), milestone_key), &milestone_vec);

        let next_id = id
            .checked_add(1)
            .unwrap_or_else(|| env.panic_with_error(Error::ContractIdOverflow));
        env.storage()
            .persistent()
            .set(&DataKey::NextContractId, &next_id);

        env.events().publish(
            (symbol_short!("created"), id),
            (
                item.client.clone(),
                item.freelancer.clone(),
                env.ledger().timestamp(),
            ),
        );

        BatchContractResult {
            index,
            contract_id: Some(id),
            error_code: None,
        }
    }
}

/// Returns the next available contract ID and asserts it is not already occupied.
///
/// # Errors
/// * `ContractIdCollision` - If the allocated id slot is already occupied
pub(crate) fn next_contract_id(env: &Env) -> u32 {
    let id: u32 = env
        .storage()
        .persistent()
        .get(&DataKey::NextContractId)
        .unwrap_or(1);

    if env
        .storage()
        .persistent()
        .get::<_, Contract>(&DataKey::Contract(id))
        .is_some()
    {
        env.panic_with_error(Error::ContractIdCollision);
    }

    id
}
