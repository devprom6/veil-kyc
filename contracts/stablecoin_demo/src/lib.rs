#![no_std]

use soroban_sdk::{contract, contractevent, contractimpl, contracttype, Address, Env, MuxedAddress, String};

/// SEP-41 allowance entry with expiry ledger.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowanceValue {
    pub amount: i128,
    pub expiration_ledger: u32,
}

/// SEP-41 `mint` event (admin-only extension).
#[contractevent]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintEvent {
    #[topic]
    pub to: Address,
    pub amount: i128,
}

/// SEP-41 `approve` event.
#[contractevent]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApproveEvent {
    #[topic]
    pub from: Address,
    #[topic]
    pub spender: Address,
    pub amount: i128,
    pub expiration_ledger: u32,
}

/// SEP-41 `transfer` event.
#[contractevent]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferEvent {
    #[topic]
    pub from: Address,
    #[topic]
    pub to: Address,
    pub amount: i128,
}

/// SEP-41 `burn` event.
#[contractevent]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnEvent {
    #[topic]
    pub from: Address,
    pub amount: i128,
}

/// Storage keys for the demo stablecoin.
#[contracttype]
enum DataKey {
    Initialized,
    Admin,
    Name,
    Symbol,
    Decimals,
    /// The policy_gate contract that is the *only* allowed transfer source.
    Gate,
    Balance(Address),
    Allowance(Address, Address),
}

/// Minimal SEP-41-compliant stablecoin whose value can only move through the
/// policy_gate contract.
///
/// Implements the SEP-41 function set with matching signatures (callable via
/// `soroban_sdk::token::TokenClient`), plus the admin-only `mint`, and
/// records the policy_gate address that is the *only* permitted source for
/// value-moving calls. See docs/decisions.md Day 3.
#[contract]
pub struct StablecoinDemo;

#[contractimpl]
impl StablecoinDemo {
    /// Initialize once: set the admin, metadata, and the policy_gate address
    /// that is the sole permitted transfer source.
    pub fn initialize(
        env: Env,
        admin: Address,
        name: String,
        symbol: String,
        decimals: u32,
        gate: Address,
    ) {
        if env.storage().instance().has(&DataKey::Initialized) {
            panic!("already initialized");
        }
        let store = env.storage().instance();
        store.set(&DataKey::Initialized, &true);
        store.set(&DataKey::Admin, &admin);
        store.set(&DataKey::Name, &name);
        store.set(&DataKey::Symbol, &symbol);
        store.set(&DataKey::Decimals, &decimals);
        store.set(&DataKey::Gate, &gate);
    }

    /// Admin-only mint. Demo supply is minted into policy_gate's balance so
    /// disbursements flow through the gate.
    pub fn mint(env: Env, to: Address, amount: i128) {
        admin(&env).require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }
        let balance = balance(&env, &to);
        env.storage()
            .instance()
            .set(&DataKey::Balance(to.clone()), &(balance + amount));
        MintEvent { to: to.clone(), amount }.publish(&env);
    }

    /// Current admin (panics if uninitialized).
    pub fn admin(env: Env) -> Address {
        admin(&env)
    }

    /// The policy_gate contract funds may move through.
    pub fn gate(env: Env) -> Address {
        request_gate(&env)
    }

    /// Sep-41: transfer `amount` from `from` to `to`.
    ///
    /// Only reachable in practice when `from` is the policy_gate: it is the
    /// sole address permitted as a source, and the only caller able to
    /// authenticate as itself. The gate invokes this through
    /// `verify_and_transfer` — the token cannot be moved directly.
    pub fn transfer(env: Env, from: Address, to: MuxedAddress, amount: i128) {
        require_gate_source(&env, &from);
        from.require_auth();
        do_transfer(&env, &from, &to.address(), amount);
    }

    /// Sep-41: transfer on behalf of `from` consuming `spender`'s allowance.
    /// Also restricted to the gate as source.
    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        require_gate_source(&env, &from);
        spender.require_auth();
        spend_allowance(&env, &from, &spender, amount);
        do_transfer(&env, &from, &to, amount);
    }

    /// Sep-41: burn `amount` from `from`. Restricted to the gate as source.
    pub fn burn(env: Env, from: Address, amount: i128) {
        require_gate_source(&env, &from);
        from.require_auth();
        do_burn(&env, &from, amount);
    }

    /// Sep-41: burn on behalf of `from`. Restricted to the gate as source.
    pub fn burn_from(env: Env, spender: Address, from: Address, amount: i128) {
        require_gate_source(&env, &from);
        spender.require_auth();
        spend_allowance(&env, &from, &spender, amount);
        do_burn(&env, &from, amount);
    }

    /// Sep-41: current spendable allowance of `spender` on `from`.
    pub fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        live_allowance(&env, &from, &spender)
    }

    /// Sep-41: set allowance for `spender` until `expiration_ledger`.
    pub fn approve(env: Env, from: Address, spender: Address, amount: i128, expiration_ledger: u32) {
        from.require_auth();
        let store = env.storage().instance();
        let entry = AllowanceValue {
            amount,
            expiration_ledger,
        };
        store.set(&DataKey::Allowance(from.clone(), spender.clone()), &entry);
        ApproveEvent {
            from: from.clone(),
            spender: spender.clone(),
            amount,
            expiration_ledger,
        }
        .publish(&env);
    }

    /// Sep-41: balance of `id`.
    pub fn balance(env: Env, id: Address) -> i128 {
        balance(&env, &id)
    }

    /// Sep-41: number of decimals.
    pub fn decimals(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::Decimals).expect("uninitialized")
    }

    /// Sep-41: token name.
    pub fn name(env: Env) -> String {
        env.storage().instance().get(&DataKey::Name).expect("uninitialized")
    }

    /// Sep-41: token symbol.
    pub fn symbol(env: Env) -> String {
        env.storage().instance().get(&DataKey::Symbol).expect("uninitialized")
    }
}

// ---------------------------------------------------------------------------
// Internal helpers (not public entry points)
// ---------------------------------------------------------------------------

fn admin(env: &Env) -> Address {
    env.storage().instance().get(&DataKey::Admin).expect("uninitialized")
}

fn request_gate(env: &Env) -> Address {
    env.storage().instance().get(&DataKey::Gate).expect("uninitialized")
}

/// Verify that the only-ever transfer source is the configured policy_gate.
fn require_gate_source(env: &Env, from: &Address) {
    let gate = request_gate(env);
    if from != &gate {
        panic!("transfers only reachable via policy_gate");
    }
}

fn balance(env: &Env, id: &Address) -> i128 {
    env.storage()
        .instance()
        .get(&DataKey::Balance(id.clone()))
        .unwrap_or(0)
}

fn do_transfer(env: &Env, from: &Address, to: &Address, amount: i128) {
    if amount < 0 {
        panic!("amount must be non-negative");
    }
    let store = env.storage().instance();
    let from_balance = balance(env, from);
    if from_balance < amount {
        panic!("insufficient balance");
    }
    store.set(&DataKey::Balance(from.clone()), &(from_balance - amount));
    store.set(&DataKey::Balance(to.clone()), &(balance(env, to) + amount));

    TransferEvent {
        from: from.clone(),
        to: to.clone(),
        amount,
    }
    .publish(env);
}

fn do_burn(env: &Env, from: &Address, amount: i128) {
    if amount < 0 {
        panic!("amount must be non-negative");
    }
    let store = env.storage().instance();
    let from_balance = balance(env, from);
    if from_balance < amount {
        panic!("insufficient balance");
    }
    store.set(&DataKey::Balance(from.clone()), &(from_balance - amount));

    BurnEvent {
        from: from.clone(),
        amount,
    }
    .publish(env);
}

fn live_allowance(env: &Env, from: &Address, spender: &Address) -> i128 {
    let stored: Option<AllowanceValue> = env
        .storage()
        .instance()
        .get(&DataKey::Allowance(from.clone(), spender.clone()));
    match stored {
        Some(entry) => {
            if entry.expiration_ledger < env.ledger().sequence() {
                0
            } else {
                entry.amount
            }
        }
        None => 0,
    }
}

fn spend_allowance(env: &Env, from: &Address, spender: &Address, amount: i128) {
    let store = env.storage().instance();
    let current = live_allowance(env, from, spender);
    if current < amount {
        panic!("insufficient allowance");
    }
    store.set(
        &DataKey::Allowance(from.clone(), spender.clone()),
        &AllowanceValue {
            amount: current - amount,
            expiration_ledger: env.ledger().sequence(),
        },
    );
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    /// env, admin, gate, token_id
    fn setup_env() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let gate = Address::generate(&env);

        let token_id = env.register(StablecoinDemo, ());
        let token = StablecoinDemoClient::new(&env, &token_id);
        token.initialize(
            &admin,
            &String::from_str(&env, "Veil Demo USD"),
            &String::from_str(&env, "VDUSD"),
            &7u32,
            &gate,
        );

        (env, admin, gate, token_id)
    }

    #[test]
    fn metadata_after_initialize() {
        let (env, _admin, _gate, token_id) = setup_env();
        let token = StablecoinDemoClient::new(&env, &token_id);
        assert_eq!(token.name(), String::from_str(&env, "Veil Demo USD"));
        assert_eq!(token.symbol(), String::from_str(&env, "VDUSD"));
        assert_eq!(token.decimals(), 7);
        assert_eq!(token.balance(&_gate), 0);
    }

    #[test]
    fn mint_credits_balance() {
        let (env, _admin, gate, token_id) = setup_env();
        let token = StablecoinDemoClient::new(&env, &token_id);
        token.mint(&gate, &1000i128);
        assert_eq!(token.balance(&gate), 1000);
    }

    #[test]
    fn gate_source_can_transfer() {
        let (env, _admin, gate, token_id) = setup_env();
        let token = StablecoinDemoClient::new(&env, &token_id);
        let recipient = Address::generate(&env);

        token.mint(&gate, &1000i128);
        token.transfer(&gate, &MuxedAddress::from(recipient.clone()), &100i128);

        assert_eq!(token.balance(&gate), 900);
        assert_eq!(token.balance(&recipient), 100);
    }

    #[test]
    #[should_panic(expected = "transfers only reachable via policy_gate")]
    fn non_gate_holder_transfers_rejected() {
        // The token can only move through the policy_gate: a plain holder
        // cannot transfer its own balance directly.
        let (env, _admin, _gate, token_id) = setup_env();
        let token = StablecoinDemoClient::new(&env, &token_id);
        let holder = Address::generate(&env);
        let recipient = Address::generate(&env);

        token.mint(&holder, &100i128);
        token.transfer(&holder, &MuxedAddress::from(recipient.clone()), &50i128);
    }

    #[test]
    fn approve_then_gate_transfer_from() {
        let (env, _admin, gate, token_id) = setup_env();
        let token = StablecoinDemoClient::new(&env, &token_id);
        let spender = Address::generate(&env);
        let recipient = Address::generate(&env);

        token.mint(&gate, &1000i128);
        // The gate authorizes spender to move part of its holding.
        token.approve(&gate, &spender, &200i128, &u32::MAX);
        assert_eq!(token.allowance(&gate, &spender), 200);

        token.transfer_from(&spender, &gate, &recipient, &50i128);
        assert_eq!(token.balance(&recipient), 50);
        assert_eq!(token.allowance(&gate, &spender), 150);
    }

    #[test]
    #[should_panic(expected = "insufficient balance")]
    fn insufficient_balance_panics() {
        let (env, _admin, gate, token_id) = setup_env();
        let token = StablecoinDemoClient::new(&env, &token_id);
        let recipient = Address::generate(&env);

        token.mint(&gate, &10i128);
        token.transfer(&gate, &MuxedAddress::from(recipient.clone()), &11i128);
    }

    #[test]
    #[should_panic(expected = "already initialized")]
    fn double_initialize_rejected() {
        let (env, admin, gate, token_id) = setup_env();
        let token = StablecoinDemoClient::new(&env, &token_id);
        token.initialize(
            &admin,
            &String::from_str(&env, "Veil Demo EUR"),
            &String::from_str(&env, "VDEUR"),
            &7u32,
            &gate,
        );
    }
}