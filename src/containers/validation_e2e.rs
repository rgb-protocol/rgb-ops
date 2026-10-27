//! Validation of a transfer whose transition script reads the global state of
//! the contract, the only contract state the RGB VM reads.

use aluvm::isa::Instr;
use aluvm::library::{Lib, LibSite};
use amplify::confinement::{
    Confined, LargeVec, NonEmptyOrdMap, NonEmptyOrdSet, NonEmptyVec, SmallBlob,
};
use amplify::num::{u24, u5};
use rgb::assignments::AssignVec;
use rgb::bitcoin::blockdata::opcodes::all::OP_RETURN;
use rgb::bitcoin::hashes::Hash;
use rgb::bitcoin::{
    absolute, transaction, Amount as Sats, OutPoint, ScriptBuf, Sequence, Transaction as Tx, TxIn,
    TxOut, Witness,
};
use rgb::commit_verify::mpc::{self, MerkleBlock, MerkleTree, MultiSource};
use rgb::commit_verify::{EmbedCommitVerify, TryCommitVerify};
use rgb::dbc::opret::OpretFirst;
use rgb::validation::{
    DbcProof, EAnchor, Failure, SchemaDefinition, SchemaRules, ValidationConfig, ValidationError,
};
use rgb::vm::RgbIsa;
use rgb::{
    Assign, AssignmentDetails, AssignmentType, Assignments, ChainNet, Genesis, GenesisSchema,
    GenesisSeal, GlobalDetails, GlobalState, GlobalStateSchema, GlobalStateType, GraphSeal, Inputs,
    KnownTransition, Occurrences, Operation, Opout, OwnedStateSchema, RevealedData, Schema,
    Transition, TransitionBundle, TransitionDetails, TransitionSchema, TransitionType,
    TypedAssigns, VoidState,
};
use strict_encoding::StrictDumb;

use crate::containers::{BuilderSeal, ConsignmentVer, TerminalSeals, Transfer, WitnessBundle};
use crate::contract::FilteredContractState;
use crate::stl::{rgb_contract_stl, StandardTypes};
use crate::Txid;

const LOG: GlobalStateType = GlobalStateType::with(1000);
const COUNT: GlobalStateType = GlobalStateType::with(1001);
const DEPTH: GlobalStateType = GlobalStateType::with(1002);
const EXPECT: GlobalStateType = GlobalStateType::with(1003);
const RIGHT: AssignmentType = AssignmentType::with(4000);
const MOVE: TransitionType = TransitionType::with(10000);

/// Fails with errno 1 unless the contract has `COUNT` entries of `LOG`, with
/// errno 2 unless it has one at depth `DEPTH`, and with errno 3 unless that
/// entry is `EXPECT`.
fn script() -> Lib {
    let code = rgb::rgbasm! {
        put     a8[0],1;
        put     a8[1],0;
        put     a16[0],0;
        ldg     COUNT,a8[1],s16[0];
        extr    s16[0],a32[1],a16[0];
        cnc     LOG,a16[0];
        eq.n    a32[0],a32[1];
        test;
        put     a8[0],2;
        ldg     DEPTH,a8[1],s16[1];
        extr    s16[1],a32[2],a16[0];
        ldc     LOG,a32[2],s16[2];
        put     a8[0],3;
        ldg     EXPECT,a8[1],s16[3];
        eq      s16[2],s16[3];
        test;
        ret;
    };
    Lib::assemble::<Instr<RgbIsa<FilteredContractState>>>(&code).unwrap()
}

/// A schema whose contract sees only the 2 most recent entries of `LOG`.
fn rules() -> SchemaRules {
    let types = StandardTypes::with(rgb_contract_stl());
    let global = |name, max_items: u32| GlobalDetails {
        global_state_schema: GlobalStateSchema {
            sem_id: types.get("RGBContract.Amount"),
            max_items: u24::with(max_items),
        },
        name,
    };
    let script = script();
    let schema = Schema {
        ffv: zero!(),
        name: tn!("ReadsGlobalState"),
        meta_types: none!(),
        global_types: tiny_bmap! {
            LOG => global(fname!("log"), 2),
            COUNT => global(fname!("count"), 1),
            DEPTH => global(fname!("depth"), 1),
            EXPECT => global(fname!("expect"), 1),
        },
        owned_types: tiny_bmap! {
            RIGHT => AssignmentDetails {
                owned_state_schema: OwnedStateSchema::Declarative,
                name: fname!("right"),
                default_transition: MOVE,
            },
        },
        genesis: GenesisSchema {
            metadata: none!(),
            globals: tiny_bmap! { LOG => Occurrences::OnceOrMore },
            assignments: tiny_bmap! { RIGHT => Occurrences::Once },
            validator: None,
        },
        transitions: tiny_bmap! {
            MOVE => TransitionDetails {
                transition_schema: TransitionSchema {
                    metadata: none!(),
                    globals: tiny_bmap! {
                        LOG => Occurrences::NoneOrMore,
                        COUNT => Occurrences::Once,
                        DEPTH => Occurrences::Once,
                        EXPECT => Occurrences::Once,
                    },
                    inputs: tiny_bmap! { RIGHT => Occurrences::Once },
                    assignments: tiny_bmap! { RIGHT => Occurrences::Once },
                    validator: Some(LibSite::with(0, script.id())),
                },
                name: fname!("move"),
            },
        },
        default_assignment: None,
    };
    let scripts = Confined::from_checked(bmap! { script.id() => script });
    SchemaDefinition::new(schema, types.libs(), scripts)
        .verify()
        .unwrap()
}

fn globals(entries: &[(GlobalStateType, u64)]) -> GlobalState {
    let mut globals = GlobalState::default();
    for &(ty, value) in entries {
        let data = RevealedData::new(SmallBlob::from_checked(value.to_le_bytes().to_vec()));
        globals.add_state(ty, data).unwrap();
    }
    globals
}

fn right<Seal: rgb::ExposedSeal>(seal: Seal) -> Assignments<Seal> {
    let mut assignments = Assignments::default();
    let assign = Assign::revealed(seal, VoidState::default());
    assignments
        .insert(RIGHT, TypedAssigns::Declarative(AssignVec::with(NonEmptyVec::with(assign))))
        .unwrap();
    assignments
}

/// Commits `transition` in a witness transaction which spends `spent` and
/// sends the right of `transition` to its output 1.
fn witness_bundle(transition: Transition, spends: Opout, spent: OutPoint) -> WitnessBundle {
    let contract_id = transition.contract_id;
    let opid = transition.id();
    let bundle = TransitionBundle {
        input_map: NonEmptyOrdMap::from_checked(bmap! { spends => opid }),
        known_transitions: NonEmptyVec::with(KnownTransition::new(opid, transition)),
    };
    let protocol_id = mpc::ProtocolId::from(contract_id);
    let message = mpc::Message::from(bundle.bundle_id());
    let tree = MerkleTree::try_commit(&MultiSource {
        min_depth: u5::with(3),
        messages: Confined::from_checked(bmap! { protocol_id => message }),
        static_entropy: Some(1),
    })
    .unwrap();
    let mpc_proof = MerkleBlock::from(&tree)
        .to_merkle_proof(protocol_id)
        .unwrap();
    let commitment = mpc_proof.convolve(protocol_id, message).unwrap();
    let output = |value, script_pubkey| TxOut {
        value: Sats::from_sat(value),
        script_pubkey,
    };
    let mut opret = ScriptBuf::new();
    opret.push_opcode(OP_RETURN);
    let mut tx = Tx {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: spent,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![output(0, opret), output(1_000, ScriptBuf::new())],
    };
    let opret =
        <Tx as EmbedCommitVerify<mpc::Commitment, OpretFirst>>::embed_commit(&mut tx, &commitment)
            .unwrap();
    WitnessBundle {
        tx,
        spv_proof: None,
        anchor: EAnchor::new(mpc_proof, DbcProof::Opret(opret)),
        bundle,
    }
}

/// A transfer of a genesis with `LOG` entries 10 and 20, then a transition
/// which adds 30, then one which claims that the contract has `count` entries
/// of `LOG` and `expect` at `depth`.
fn transfer(rules: &SchemaRules, count: u64, depth: u64, expect: u64) -> Transfer {
    let funding = Txid::from_byte_array([1; 32]);
    let mut genesis = Genesis::strict_dumb();
    genesis.schema_id = rules.schema().schema_id();
    genesis.chain_net = ChainNet::BitcoinRegtest;
    genesis.globals = globals(&[(LOG, 10), (LOG, 20)]);
    genesis.assignments = right(GenesisSeal::with_blinding(funding, 0, 1));
    let contract_id = genesis.contract_id();

    let mut bundles = vec![];
    let mut spends = Opout::new(genesis.id(), RIGHT, 0);
    let mut spent = OutPoint::new(funding, 0);
    let mut seals = vec![];
    let claims = [
        // The genesis entries, 20 at depth 0 and 10 at depth 1.
        &[(LOG, 30), (COUNT, 2), (DEPTH, 1), (EXPECT, 10)][..],
        // The limit keeps 30 at depth 0 and 20 at depth 1.
        &[(COUNT, count), (DEPTH, depth), (EXPECT, expect)][..],
    ];
    for (no, claims) in claims.into_iter().enumerate() {
        let seal = GraphSeal::with_blinded_vout(1, no as u64);
        let mut transition = Transition::strict_dumb();
        transition.contract_id = contract_id;
        transition.transition_type = MOVE;
        transition.globals = globals(claims);
        transition.inputs = Inputs::from(NonEmptyOrdSet::with(spends));
        transition.assignments = right(seal);
        let opid = transition.id();
        let witness_bundle = witness_bundle(transition, spends, spent);
        spends = Opout::new(opid, RIGHT, 0);
        spent = OutPoint::new(witness_bundle.tx.compute_txid(), 1);
        bundles.push(witness_bundle);
        seals.push(seal);
    }
    let last = bundles.last().unwrap().bundle.bundle_id();
    let terminal = BuilderSeal::Revealed(*seals.last().unwrap());
    Transfer {
        version: ConsignmentVer::V1,
        transfer: true,
        terminals: Confined::from_checked(bmap! {
            last => TerminalSeals::from(NonEmptyVec::with(terminal))
        }),
        genesis,
        bundles: LargeVec::from_checked(bundles),
    }
}

#[test]
fn validation_runs_scripts_which_read_global_state() {
    let rules = rules();
    let config = ValidationConfig {
        chain_net: ChainNet::BitcoinRegtest,
        safe_height: None,
        build_opouts_dag: false,
    };
    let errno = |count, depth, expect| match transfer(&rules, count, depth, expect)
        .validate_deterministic(&rules, &config)
    {
        Ok(_) => None,
        Err(ValidationError::InvalidConsignment(Failure::ScriptFailure(_, errno, _))) => errno,
        Err(err) => panic!("unexpected error {err:?}"),
    };
    assert_eq!(errno(2, 0, 30), None);
    assert_eq!(errno(2, 1, 20), None);
    assert_eq!(errno(3, 0, 30), Some(1));
    assert_eq!(errno(2, 2, 10), Some(2));
    assert_eq!(errno(2, 0, 20), Some(3));
}
