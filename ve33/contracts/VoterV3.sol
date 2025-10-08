// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./libraries/Math.sol";
import "./interfaces/IBribe.sol";
import "./interfaces/IERC20.sol";
import "./interfaces/IPairInfo.sol";
import "./interfaces/IPairFactory.sol";
import "./interfaces/IVotingEscrow.sol";
import "./interfaces/IGaugeManager.sol";
import "./interfaces/IPermissionsRegistry.sol";
import "./interfaces/ITokenHandler.sol";
import {HybraTimeLibrary} from "./libraries/HybraTimeLibrary.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";

contract VoterV3 is OwnableUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    address public _ve; // the ve token that governs these contracts
    address internal base; // $the token
    address public permissionRegistry; // registry to check accesses
    address public tokenHandler;
    uint256 public maxVotingNum;
    uint public EPOCH_DURATION;
    uint256 internal constant MIN_VOTING_NUM = 10;
    IGaugeManager public gaugeManager;

    mapping(uint256 => mapping(address => uint256)) public votes; // nft      => pool     => votes
    mapping(uint256 => address[]) public poolVote; // nft      => pools

    mapping(address => uint256) public weights;
    uint256 public totalWeight;
    mapping(uint256 => uint256) public usedWeights;

    mapping(uint256 => uint256) public lastVoted; // nft      => timestamp of last vote (this is shifted to thursday of that epoc)
    mapping(uint256 => uint256) public lastVotedTimestamp; // nft      => timestamp of last vote

    event Voted(address indexed voter, uint256 tokenId, uint256 weight);
    event Abstained(uint256 tokenId, uint256 weight);
    event SetPermissionRegistry(address indexed old, address indexed latest);

    constructor() {}

    // function initialize(address __ve, address _pairFactory, address  _gaugeFactory, address _bribes, address _tokenHandler) initializer public {
    function initialize(
        address __ve,
        address _tokenHandler,
        address _gaugeManager,
        address _permissionRegistry
    ) public initializer {
        __Ownable_init();
        __ReentrancyGuard_init();
        _ve = __ve;
        base = IVotingEscrow(__ve).token();
        gaugeManager = IGaugeManager(_gaugeManager);
        permissionRegistry = _permissionRegistry;
        tokenHandler = _tokenHandler;
        maxVotingNum = 30;
        EPOCH_DURATION = HybraTimeLibrary.WEEK;
    }

    /* -----------------------------------------------------------------------------
    --------------------------------------------------------------------------------
    --------------------------------------------------------------------------------
                                    MODIFIERS
    --------------------------------------------------------------------------------
    --------------------------------------------------------------------------------
    ----------------------------------------------------------------------------- */

    modifier VoterAdmin() {
        require(
            IPermissionsRegistry(permissionRegistry).hasRole(
                "VOTER_ADMIN",
                msg.sender
            ),
            "VOTER_ADMIN"
        );
        _;
    }

    modifier Governance() {
        require(
            IPermissionsRegistry(permissionRegistry).hasRole(
                "GOVERNANCE",
                msg.sender
            ),
            "GOVERNANCE"
        );
        _;
    }

    modifier GenesisManager() {
        require(
            IPermissionsRegistry(permissionRegistry).hasRole(
                "GENESIS_MANAGER",
                msg.sender
            ),
            "GENESIS_MANAGER"
        );
        _;
    }

    /* -----------------------------------------------------------------------------
    --------------------------------------------------------------------------------
    --------------------------------------------------------------------------------
                                    VoterAdmin
    --------------------------------------------------------------------------------
    --------------------------------------------------------------------------------
    ----------------------------------------------------------------------------- */

    /// @notice Set a new PermissionRegistry
    function setPermissionsRegistry(
        address _permissionRegistry
    ) external VoterAdmin {
        require(_permissionRegistry.code.length > 0, "CODELEN");
        require(_permissionRegistry != address(0), "ZA");
        emit SetPermissionRegistry(permissionRegistry, _permissionRegistry);
        permissionRegistry = _permissionRegistry;
    }

    function setMaxVotingNum(uint256 _maxVotingNum) external VoterAdmin {
        require(_maxVotingNum >= MIN_VOTING_NUM, "LOW_VOTE");
        maxVotingNum = _maxVotingNum;
    }

    /* -----------------------------------------------------------------------------
    --------------------------------------------------------------------------------
    --------------------------------------------------------------------------------
                                    USER INTERACTION
    --------------------------------------------------------------------------------
    --------------------------------------------------------------------------------
    ----------------------------------------------------------------------------- */

    /// @notice Reset the votes of a given TokenID
    function reset(
        uint256 _tokenId
    ) external onlyNewEpoch(_tokenId) nonReentrant {
        require(
            IVotingEscrow(_ve).isApprovedOrOwner(msg.sender, _tokenId),
            "NAO"
        );
        _reset(_tokenId);
        IVotingEscrow(_ve).abstain(_tokenId);
    }

    function _reset(uint256 _tokenId) internal {
        address[] storage _poolVote = poolVote[_tokenId];
        uint256 _poolVoteCnt = _poolVote.length;
        uint256 _totalWeight = 0;

        for (uint256 i = 0; i < _poolVoteCnt; i++) {
            address _pool = _poolVote[i];
            uint256 _votes = votes[_tokenId][_pool];

            if (_votes != 0) {
                weights[_pool] -= _votes;

                votes[_tokenId][_pool] -= _votes;
                address internal_bribe = gaugeManager
                    .fetchInternalBribeFromPool(_pool);
                address external_bribe = gaugeManager
                    .fetchExternalBribeFromPool(_pool);
                IBribe(internal_bribe).withdraw(uint256(_votes), _tokenId);
                IBribe(external_bribe).withdraw(uint256(_votes), _tokenId);

                // decrease totalWeight irrespective of gauge is killed/alive for this current pool
                _totalWeight += _votes;

                emit Abstained(_tokenId, _votes);
            }
        }
        totalWeight -= _totalWeight;
        usedWeights[_tokenId] = 0;
        delete poolVote[_tokenId];
    }

    /// @notice Recast the saved votes of a given TokenID
    function poke(uint256 _tokenId) external nonReentrant {
        uint256 _timestamp = block.timestamp;
        if (_timestamp <= HybraTimeLibrary.epochVoteStart(_timestamp)) {
            revert("DW");
        }
        require(
            IVotingEscrow(_ve).isApprovedOrOwner(msg.sender, _tokenId) ||
                msg.sender == _ve,
            "NAO||VE"
        );
        address[] memory _poolVote = poolVote[_tokenId];
        uint256 _poolCnt = _poolVote.length;
        uint256[] memory _weights = new uint256[](_poolCnt);

        for (uint256 i = 0; i < _poolCnt; i++) {
            _weights[i] = votes[_tokenId][_poolVote[i]];
        }

        _vote(_tokenId, _poolVote, _weights);
    }

    /// @notice Vote for pools
    /// @param  _tokenId    veNFT tokenID used to vote
    /// @param  _poolVote   array of LPs addresses to vote  (eg.: [sAMM usdc-usdt   , sAMM busd-usdt, vAMM wbnb-the ,...])
    /// @param  _weights    array of weights for each LPs   (eg.: [10               , 90            , 45             ,...])
    function vote(
        uint256 _tokenId,
        address[] calldata _poolVote,
        uint256[] calldata _weights
    ) external onlyNewEpoch(_tokenId) nonReentrant {
        require(
            IVotingEscrow(_ve).isApprovedOrOwner(msg.sender, _tokenId),
            "NAO"
        );
        require(_poolVote.length == _weights.length, "MISMATCH_LEN");
        require(_poolVote.length <= maxVotingNum, "EXCEEDS");
        uint256 _timestamp = block.timestamp;

        _vote(_tokenId, _poolVote, _weights);
        lastVoted[_tokenId] = HybraTimeLibrary.epochStart(block.timestamp) + 1;
        lastVotedTimestamp[_tokenId] = block.timestamp;
    }

    function _vote(
        uint256 _tokenId,
        address[] memory _poolVote,
        uint256[] memory _weights
    ) internal {
        _reset(_tokenId);
        uint256 _poolCnt = _poolVote.length;
        uint256 _weight = IVotingEscrow(_ve).balanceOfNFT(_tokenId);
        uint256 _totalVoteWeight = 0;
        uint256 _usedWeight = 0;

        for (uint i = 0; i < _poolCnt; i++) {
            _totalVoteWeight += _weights[i];
        }

        for (uint256 i = 0; i < _poolCnt; i++) {
            address _pool = _poolVote[i];

            if (gaugeManager.isGaugeAliveForPool(_pool)) {
                uint256 _poolWeight = (_weights[i] * _weight) /
                    _totalVoteWeight;

                require(votes[_tokenId][_pool] == 0, "ZV");
                require(_poolWeight != 0, "ZV");

                poolVote[_tokenId].push(_pool);
                weights[_pool] += _poolWeight;

                votes[_tokenId][_pool] = _poolWeight;
                address internal_bribe = gaugeManager
                    .fetchInternalBribeFromPool(_pool);
                address external_bribe = gaugeManager
                    .fetchExternalBribeFromPool(_pool);

                IBribe(internal_bribe).deposit(uint256(_poolWeight), _tokenId);
                IBribe(external_bribe).deposit(uint256(_poolWeight), _tokenId);

                _usedWeight += _poolWeight;
                emit Voted(msg.sender, _tokenId, _poolWeight);
            }
        }
        if (_usedWeight > 0) IVotingEscrow(_ve).voting(_tokenId);
        totalWeight += _usedWeight;
        usedWeights[_tokenId] = _usedWeight;
    }

    modifier onlyNewEpoch(uint256 _tokenId) {
        // ensure new epoch since last vote
        if (HybraTimeLibrary.epochStart(block.timestamp) <= lastVoted[_tokenId])
            revert("VOTED");
        if (block.timestamp <= HybraTimeLibrary.epochVoteStart(block.timestamp))
            revert("DW");
        _;
    }

    /* -----------------------------------------------------------------------------
    --------------------------------------------------------------------------------
    --------------------------------------------------------------------------------
                                    VIEW FUNCTIONS
    --------------------------------------------------------------------------------
    --------------------------------------------------------------------------------
    ----------------------------------------------------------------------------- */

    /// @notice view the total length of the pools
    function length() external view returns (uint256) {
        return gaugeManager.pools().length;
    }

    /// @notice view the total length of the voted pools given a tokenId
    function poolVoteLength(uint256 tokenId) external view returns (uint256) {
        return poolVote[tokenId].length;
    }

    function setGaugeManager(address _gaugeManager) external VoterAdmin {
        require(_gaugeManager != address(0));
        gaugeManager = IGaugeManager(_gaugeManager);
    }
}
