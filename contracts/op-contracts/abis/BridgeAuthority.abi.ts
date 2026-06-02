import { ABIDataTypes, BitcoinAbiTypes, OP_NET_ABI } from 'opnet';

export const BridgeAuthorityEvents = [
    {
        name: 'AuthorityContractsSet',
        values: [
            { name: 'depository', type: ABIDataTypes.ADDRESS },
            { name: 'wusdc', type: ABIDataTypes.ADDRESS },
            { name: 'wusdt', type: ABIDataTypes.ADDRESS },
        ],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'AuthorityGovernorUpdated',
        values: [
            { name: 'oldGov', type: ABIDataTypes.ADDRESS },
            { name: 'newGov', type: ABIDataTypes.ADDRESS },
        ],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'AuthorityGuardianUpdated',
        values: [
            { name: 'oldGuardian', type: ABIDataTypes.ADDRESS },
            { name: 'newGuardian', type: ABIDataTypes.ADDRESS },
        ],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'AuthorityPausedAll',
        values: [],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'AuthorityUnpausedAll',
        values: [],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'AuthoritySignerAdded',
        values: [{ name: 'pubKeyHash', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'AuthoritySignerRemoved',
        values: [{ name: 'pubKeyHash', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'AuthorityThresholdSet',
        values: [{ name: 'threshold', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Event,
    },
];

export const BridgeAuthorityAbi = [
    {
        name: 'setManagedContracts',
        inputs: [
            { name: 'depository', type: ABIDataTypes.ADDRESS },
            { name: 'wusdc', type: ABIDataTypes.ADDRESS },
            { name: 'wusdt', type: ABIDataTypes.ADDRESS },
        ],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'pushGovernor',
        inputs: [{ name: 'newGovernor', type: ABIDataTypes.ADDRESS }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'pushGuardian',
        inputs: [{ name: 'newGuardian', type: ABIDataTypes.ADDRESS }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'pauseAll',
        inputs: [],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'unpauseAll',
        inputs: [],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'addBridgeSigner',
        inputs: [{ name: 'pubKeyHash', type: ABIDataTypes.UINT256 }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'removeBridgeSigner',
        inputs: [{ name: 'pubKeyHash', type: ABIDataTypes.UINT256 }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'setBridgeThreshold',
        inputs: [{ name: 'threshold', type: ABIDataTypes.UINT256 }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'migrateBridgeSignerSet',
        inputs: [
            { name: 'addHash', type: ABIDataTypes.UINT256 },
            { name: 'newThreshold', type: ABIDataTypes.UINT256 },
        ],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'setUpgradeAuthority',
        inputs: [{ name: 'newUpgradeAuthority', type: ABIDataTypes.ADDRESS }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'proposeUpgrade',
        inputs: [],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'cancelProposedUpgrade',
        inputs: [],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'upgradeAuthority',
        constant: true,
        inputs: [],
        outputs: [{ name: 'upgradeAuthority', type: ABIDataTypes.ADDRESS }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'pendingUpgradeAuthorized',
        constant: true,
        inputs: [],
        outputs: [{ name: 'pendingUpgradeAuthorized', type: ABIDataTypes.BOOL }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'governor',
        constant: true,
        inputs: [],
        outputs: [{ name: 'governor', type: ABIDataTypes.ADDRESS }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'guardian',
        constant: true,
        inputs: [],
        outputs: [{ name: 'guardian', type: ABIDataTypes.ADDRESS }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'depository',
        constant: true,
        inputs: [],
        outputs: [{ name: 'depository', type: ABIDataTypes.ADDRESS }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'wusdc',
        constant: true,
        inputs: [],
        outputs: [{ name: 'wusdc', type: ABIDataTypes.ADDRESS }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'wusdt',
        constant: true,
        inputs: [],
        outputs: [{ name: 'wusdt', type: ABIDataTypes.ADDRESS }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'storageVersion',
        constant: true,
        inputs: [],
        outputs: [{ name: 'storageVersion', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    ...BridgeAuthorityEvents,
    ...OP_NET_ABI,
];

export default BridgeAuthorityAbi;
