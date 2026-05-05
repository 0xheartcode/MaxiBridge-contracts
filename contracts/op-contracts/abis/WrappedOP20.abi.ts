import { ABIDataTypes, BitcoinAbiTypes, OP_NET_ABI } from 'opnet';

export const WrappedOP20Events = [
    {
        name: 'BridgeDepositoryUpdated',
        values: [
            { name: 'oldAddr', type: ABIDataTypes.ADDRESS },
            { name: 'newAddr', type: ABIDataTypes.ADDRESS },
        ],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'GovernorUpdated',
        values: [
            { name: 'oldAddr', type: ABIDataTypes.ADDRESS },
            { name: 'newAddr', type: ABIDataTypes.ADDRESS },
        ],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'AuthorityAddressSet',
        values: [{ name: 'authority', type: ABIDataTypes.ADDRESS }],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'MinterGranted',
        values: [{ name: 'minter', type: ABIDataTypes.ADDRESS }],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'MinterRevoked',
        values: [{ name: 'minter', type: ABIDataTypes.ADDRESS }],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'Paused',
        values: [],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'Unpaused',
        values: [],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'Minted',
        values: [
            { name: 'to', type: ABIDataTypes.ADDRESS },
            { name: 'amount', type: ABIDataTypes.UINT256 },
            { name: 'to', type: ABIDataTypes.ADDRESS },
            { name: 'amount', type: ABIDataTypes.UINT256 },
        ],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'BurnedForRelease',
        values: [
            { name: 'user', type: ABIDataTypes.ADDRESS },
            { name: 'amount', type: ABIDataTypes.UINT256 },
            { name: 'ethRecipient', type: ABIDataTypes.BYTES },
            { name: 'destChainId', type: ABIDataTypes.UINT32 },
            { name: 'burnNonce', type: ABIDataTypes.UINT256 },
        ],
        type: BitcoinAbiTypes.Event,
    },
];

export const WrappedOP20Abi = [
    {
        name: 'setBridgeDepository',
        inputs: [{ name: 'newBridge', type: ABIDataTypes.ADDRESS }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'setGovernor',
        inputs: [{ name: 'newGovernor', type: ABIDataTypes.ADDRESS }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'setAuthorityAddress',
        inputs: [{ name: 'authority', type: ABIDataTypes.ADDRESS }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'grantMinter',
        inputs: [{ name: 'minter', type: ABIDataTypes.ADDRESS }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'revokeMinter',
        inputs: [{ name: 'minter', type: ABIDataTypes.ADDRESS }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'isMinter',
        constant: true,
        inputs: [],
        outputs: [{ name: 'authorized', type: ABIDataTypes.BOOL }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'authorityAddress',
        constant: true,
        inputs: [],
        outputs: [{ name: 'authority', type: ABIDataTypes.ADDRESS }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'setPaused',
        inputs: [{ name: 'paused', type: ABIDataTypes.BOOL }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'mintTo',
        inputs: [
            { name: 'to', type: ABIDataTypes.ADDRESS },
            { name: 'amount', type: ABIDataTypes.UINT256 },
        ],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'burnForRelease',
        inputs: [
            { name: 'ethRecipient', type: ABIDataTypes.BYTES32 },
            { name: 'amount', type: ABIDataTypes.UINT256 },
            { name: 'destChainId', type: ABIDataTypes.UINT32 },
        ],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'bridgeDepository',
        constant: true,
        inputs: [],
        outputs: [{ name: 'depository', type: ABIDataTypes.ADDRESS }],
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
        name: 'burnNonce',
        constant: true,
        inputs: [],
        outputs: [{ name: 'burnNonce', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'storageVersion',
        constant: true,
        inputs: [],
        outputs: [{ name: 'storageVersion', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'paused',
        constant: true,
        inputs: [],
        outputs: [{ name: 'paused', type: ABIDataTypes.BOOL }],
        type: BitcoinAbiTypes.Function,
    },
    ...WrappedOP20Events,
    ...OP_NET_ABI,
];

export default WrappedOP20Abi;
