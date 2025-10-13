## High Severity Findings

Note: Not all issues are guaranteed to be correct

### LockedBalance Staleness Leading to Transfer Reverts

**Severity:** High  

**Affected Contract(s):**
- `GrowthHYBR`

**Affected Function(s):**
- `withdraw`

**Description:**

When a user withdraws gHYBR shares, the contract burns their tokens without cleaning up any expired or active transfer locks, leaving `lockedBalance` potentially greater than their remaining `balanceOf`. Subsequent transfers trigger a check `available = balanceOf – lockedBalance` inside `_beforeTokenTransfer`. If `lockedBalance` exceeds `balanceOf`, this subtraction underflows to zero (in Solidity 0.8+ it reverts), permanently blocking further transfers for the user.

**Root Cause:**

The `withdraw` function burns shares (invoking `_beforeTokenTransfer` with `to == address(0)`, which skips lock cleanup) but does not call `_cleanExpired` or otherwise decrement `lockedBalance`. Lock cleanup only happens during non-burn token transfers, so burned shares leave stale lock amounts in `lockedBalance`.

**Impact:**

A user who withdraws (burns) shares while any locks—expired or not—still reside in `userLocks` will have `lockedBalance` exceed their token balance. Any attempt to transfer remaining tokens thereafter reverts, effectively freezing the user’s gHYBR tokens indefinitely.

---

### Stale Votes Can Be Recast Outside Intended Voting Window

**Severity:** High  

**Affected Contract(s):**
- `VoterV3`

**Affected Function(s):**
- `poke`

**Description:**

The `poke` function only checks that the current timestamp is after the start of the voting window (`epochVoteStart`) and never enforces that it is before the window’s end (`epochVoteEnd`). Neither `poke` nor the underlying `_vote` (or `_reset`) functions include an upper-bound time check. As a result, token holders can call `poke` at any time after the window opens—long after the intended voting period—to recast stale votes and manipulate gauge weights outside the designated timeframe.

**Root Cause:**

Absence of an upper-bound cutoff on `block.timestamp` (no check against `epochVoteEnd`) in `poke` or related voting functions.

**Impact:**

Allows votes to be refreshed and weights to be redistributed arbitrarily long after the official voting period, distorting gauge allocation and reward distribution.

---

### Omitted Rollover from Reward Rate Calculation

**Severity:** High  

**Affected Contract(s):**
- `GaugeCL`

**Affected Function(s):**
- `notifyRewardAmount`

**Description:**

The notifyRewardAmount function updates the reward rate for distributing tokens across an epoch. It computes totalRewardAmount by summing the newly provided rewardAmount with the pool’s rollover (undistributed prior funds), but when calculating per-second rewardRate, it only uses rewardAmount (and pending epoch rewards in the ongoing-period branch). Thus leftover rollover tokens inflate the reserve but are never scheduled into the drip rate, leaving them undistributed.

**Root Cause:**

The function fails to include clPool.rollover() in the numerator when calculating rewardRate in both the post-expiry and ongoing-period branches, even though it adds rollover to the rewardReserve.

**Impact:**

Leftover rollover tokens remain stranded in the pool’s reserve and never reach stakers, causing unreleased rewards and potentially misleading accounting. Over time, this can lock tokens indefinitely, reducing distributor ROI and undermining protocol trust.

---

### Unrestricted CL Gauge Registration via Missing Factory Validation

**Severity:** High    

**Affected Contract(s):**
- `GaugeManager`

**Affected Function(s):**
- `_createGauge`

**Description:**

For gaugeType 1 (concentrated liquidity), the function unconditionally sets isPair to true and never verifies that the provided `_pool` address was actually created by the authorized CL pool factory. As a result, an attacker can deploy a malicious contract implementing token0(), token1(), and setGaugeAndPositionManager(), satisfy whitelist/connector checks, and register it as a CL gauge.

**Root Cause:**

An incorrect assumption that all gaugeType 1 pools are valid bypasses the factory-based isPair check, trusting the caller-supplied pool address without on-chain validation.

**Impact:**

Attackers can register arbitrary contracts as CL gauges, potentially siphoning or redirecting reward tokens, corrupting bribe distributions, or otherwise disrupting gauge-based reward and governance mechanisms.

---

### Denial-of-Service via Self-Delegation Signature Replay

**Severity:** High    

**Affected Contract(s):**
- `VotingEscrow`

**Affected Function(s):**
- `delegateBySig`

**Description:**

The `delegateBySig` function uses `require(delegatee != msg.sender)` to prevent self-delegation, but it should compare `delegatee` against the recovered `signatory`. A third party can submit a valid “self-delegate” signature (where `delegatee == signatory`) on behalf of the signer. Since `msg.sender` is the caller (the attacker), the check passes, consumes the signer’s nonce, and `_delegate` silently no-ops when delegating to oneself. This burns the signer’s nonce and prevents them from ever using delegateBySig again.

**Root Cause:**

The self-delegation check compares `delegatee` to `msg.sender` instead of to the recovered signature’s `signatory`, allowing third-party callers to bypass the intended restriction.

**Impact:**

An attacker with a user’s self-delegation signature can perform a replay attack, consuming the user’s nonce and denying them the ability to delegate via signature in the future, leading to a denial-of-service.

---

### poke() Bypasses onlyNewEpoch Enforcement

**Severity:** High  

**Affected Contract(s):**
- `VoterV3`

**Affected Function(s):**
- `poke`

**Description:**

The external poke() function invokes the internal `_vote` logic once the voting window opens, but it lacks the onlyNewEpoch modifier and does not update lastVoted. This allows a token holder to call poke() repeatedly within the same epoch and refresh or change their vote weights mid‐epoch.

**Root Cause:**

poke() omits the onlyNewEpoch guard and does not update the lastVoted mapping, bypassing the one‐vote‐per‐epoch enforcement.

**Impact:**

A voter can adjust their voting power multiple times in a single epoch—e.g., by acquiring more veNFT balance after the epoch start and then calling poke() to immediately apply the extra weight—undermining snapshot voting and potentially skewing gauge distributions.

---

### Poke Bypass Allows Multiple Resets

**Severity:** High   

**Affected Contract(s):**
- `VoterV3`

**Affected Function(s):**
- `poke`

**Description:**

The `poke` function calls the internal `_vote` (which itself calls `_reset`) without the `onlyNewEpoch` modifier or updating `lastVoted`. This allows anyone who can call `poke` on an approved token to repeatedly trigger `_reset`—withdraw bribes, zero `usedWeights`, and then re-deposit votes—multiple times within the same epoch.

**Root Cause:**

`poke` omits the `onlyNewEpoch` guard and does not update `lastVoted`, while `_vote` always invokes `_reset` unconditionally.

**Impact:**

Malicious actors can call `poke` repeatedly in a single epoch to drain bribes multiple times, disrupt vote accounting, and inflate or deflate weights improperly, undermining the voting/bribe distribution mechanism.

---

### Duplicate Token IDs Inflate Voting Weight

**Severity:** High  

**Affected Contract(s):**
- `VotingDelegationLib`

**Affected Function(s):**
- `_moveAllDelegates`

**Description:**

When creating a new checkpoint for the destination delegate in `_moveAllDelegates` (when `_isCheckpointInNewBlock` is true), the code first pushes every tokenId from the old checkpoint array (dstRepOld) into the new tokenIds array (dstRepNew), then pushes the delegator’s current tokenIds. There is no check to prevent a tokenId that appears in both lists from being added twice. Since voting weight is computed simply as tokenIds.length, a single NFT can be counted twice.

**Root Cause:**

Absence of any deduplication or uniqueness check when merging the previous checkpoint’s tokenIds list with the owner’s current tokenIds list in the new checkpoint creation branch.

**Impact:**

An attacker or delegator can inflate a delegate’s voting power by ensuring some tokenIds overlap between dstRepOld and the owner’s current holdings, causing those tokens to be double‐counted. This can lead to disproportionate voting influence.


## Medium Severity Findings

Note: Not all issues are guaranteed to be correct

### Uninitialized maturityTime Unlocks Immediate Withdrawals

**Severity:** Medium  

**Affected Contract(s):**
- `GaugeV2`

**Affected Function(s):**
- `_withdraw`

**Description:**

The `_withdraw` function includes a maturityTime check (`require(block.timestamp >= maturityTime[msg.sender])`), intended to enforce a lock period before users can withdraw. However, `maturityTime[msg.sender]` is never assigned in any deposit or mint function. As a result, it remains at its default value of 0, so the check always succeeds, allowing immediate withdrawals with no lock.

**Root Cause:**

The maturityTime mapping is never initialized or updated on deposit (or any other path), leaving all entries at zero.

**Impact:**

Users can bypass any intended locking mechanism and withdraw their tokens immediately after deposit, potentially violating protocol design and leading to financial risk or undesired behavior in dependent systems.

---

### Deposit Lock-Spam Vulnerability

**Severity:** Medium  

**Affected Contract(s):**
- `GrowthHYBR`

**Affected Function(s):**
- `deposit`

**Description:**

The deposit function allows any user to mint gHYBR shares to an arbitrary recipient and immediately applies a transfer lock via `_addTransferLock`. Because recipients cannot opt out of incoming tokens and each mint appends a new lock entry without limit or cleanup, attackers can spam deposits of minimal amounts to victim addresses, bloat their userLocks arrays, and impose unwanted transfer locks.

**Root Cause:**

Automatic, unconditional application of transfer locks on every minted gHYBR combined with unbounded growth of userLocks entries and lack of any pruning or recipient opt-out mechanism.

**Impact:**

Attackers can force victims’ userLocks arrays to grow indefinitely, leading to high gas costs or out-of-gas errors when victims interact with their locked balances, resulting in denial-of-service or permanent lock-related issues.

---

### Denial-of-Service via Unbounded Lock Cleanup

**Severity:** Medium  

**Affected Contract(s):**
- `GrowthHYBR`

**Affected Function(s):**
- `_cleanExpired`

**Description:**

The internal function `_cleanExpired` linearly scans the entire `userLocks[user]` array and compacts non‐expired locks, then pops expired entries in a while loop. Because each deposit appends a new lock with no cap on the number of locks per user, the array can grow arbitrarily large. Moreover, `_cleanExpired` is invoked automatically on every ERC20 transfer (via `_beforeTokenTransfer`), so any transfer must clean up all locks in one transaction. As the array size grows, gas costs increase linearly and can exceed the block gas limit, causing all transfers (and clean‐up attempts) to revert and freezing the user’s tokens.

**Root Cause:**

Unbounded iteration and pop operations over a dynamic array with no per‐user lock limit or batching mechanism, causing gas usage to scale linearly with array length.

**Impact:**

A malicious or heavy‐usage account can deliberately accumulate many locks to force `_cleanExpired` to run out of gas. Any subsequent token transfer or withdrawal will revert, effectively locking the user’s funds permanently. This constitutes a denial‐of‐service on token transfers for that user.

---

### Arbitrary Recipient Deposit Denial-of-Service

**Severity:** Medium  

**Affected Contract(s):**
- `GrowthHYBR`

**Affected Function(s):**
- `deposit`

**Description:**

The deposit function allows any caller to specify a recipient address (defaulting to msg.sender only when zero). Each call unconditionally appends a new UserLock entry for the specified recipient into the userLocks mapping without the recipient’s consent or any limit. An attacker can repeatedly call deposit(amount, victimAddress) to inflate the victim’s userLocks array indefinitely.

**Root Cause:**

Missing access control or consent checks on the recipient parameter in the deposit function, allowing unbounded insertion of lock entries for arbitrary addresses.

**Impact:**

An attacker can bloat a victim’s userLocks array, leading to excessive storage usage and gas costs when accessing or iterating over userLocks[victim], potentially causing denial-of-service for the victim.

## Low Severity Findings

Note: Not all issues are guaranteed to be correct

### Any issues involving:

**Admin/Privileged Role Issues:**
- Assumes malicious admin
- Requires malicious admin setting malicious contract (voter, gauge, minter, swapper, factory, gaugeRewarder, unstakedFeeModule)
- Requires admin input error / admin error
- Assumes deployment error
- Assumes compromised gauge/voter/pair contract

**User Error:**
- Requires user input error
- User error (wrong inputs, wrong addresses)
- Users donating funds (not incentivized)
- User self-DoS

**Governance/Configuration Issues:**
- Requires governance lowering parameters (maxVotingNum)
- Requires users voting for pools with killed gauges
- Requires owner/operator voting for unrealistic amounts of pools

**Other:**
- Requires TokenHandler whitelist bypass (unlikely)

### Denial-of-Service via Unbounded Loop in collectAllProtocolFees

**Severity:** Low  

**Affected Contract(s):**
- `CLFactory`

**Affected Function(s):**
- `collectAllProtocolFees`

**Description:**

The function unconditionally iterates over every pool in the dynamically growing allPools array and calls collectProtocolFees on each one. Even when a pool has zero accrued fees, each call still consumes non-trivial gas (storage reads, conditional branching, and a return). As the number of pools grows, the aggregated gas cost can exceed the block gas limit, making collectAllProtocolFees permanently uncallable by the owner.

**Root Cause:**

No cap or pruning on the allPools array and no conditional check to skip pools without fees, resulting in an unbounded loop that always pays gas per iteration.

**Impact:**

Once enough pools exist, the owner can no longer invoke collectAllProtocolFees, effectively locking up all future protocol fee collections and causing a denial-of-service for fee distribution.

---

### Skipped Weekly Emissions When update_period Is Delayed

**Severity:** Low  

**Affected Contract(s):**
- `MinterUpgradeable`

**Affected Function(s):**
- `update_period`

**Description:**

The update_period function checks if at least one WEEK has passed since the last active_period, but mints tokens for only a single week regardless of how many weeks have actually elapsed. It then jumps active_period forward to the most recent week, permanently skipping any intermediate weekly emissions.

**Root Cause:**

update_period unconditionally increments epochCount by 1 and sets active_period = (block.timestamp / WEEK) * WEEK without looping to mint for each missed week.

**Impact:**

If update_period is not called for N>1 weeks, tokens for N–1 weekly emission periods are never minted. This reduces total emission distribution, breaks expected token inflation schedules, and can unfairly disadvantage stakeholders.

---

### Denial-of-Service via Unbounded pools Array

**Severity:** Low  

**Affected Contract(s):**
- `GaugeManager`

**Affected Function(s):**
- `distributeAll`

**Description:**

The distributeAll function iterates over the entire pools array in a single unchunked loop. Since any external user can invoke createGauge/createGauges (subject only to local whitelisting checks) and each call appends a new pool entry without removal or a global cap, an attacker can bloat pools to an arbitrarily large size. Eventually, distributeAll will exhaust the block gas limit and revert, halting all reward distributions.

**Root Cause:**

No global limit or pruning mechanism for the pools array combined with public gauge-creation functions that continuously append unique pools without permission restrictions.

**Impact:**

An attacker can create a large number of valid pools to grow the pools array until distributeAll runs out of gas and reverts, resulting in a denial-of-service that prevents all users from receiving rewards.


---

### Unbounded Conversion to int128 Causes Panic Overflow in `_deposit_for`

**Severity:** Low  

**Affected Contract(s):**
- `VotingEscrow`

**Affected Function(s):**
- `_deposit_for`

**Description:**

The internal function `_deposit_for` casts the user-supplied uint `_value` directly to int128 via `int128(int256(_value))` without enforcing an upper-bound check. If `_value` exceeds the maximum positive int128 value (2^127−1), the Solidity runtime triggers a panic (Panic 0x11) and reverts the transaction unexpectedly.

**Root Cause:**

Missing validation that `_value` is less than or equal to type(int128).max before performing the uint→int128 cast.

**Impact:**

An attacker (or user with a large token balance) could call increase_amount or another deposit function with `_value` > 2^127−1, causing a panic overflow and revert. This can lead to denial-of-service for valid lock increases or deposits and unexpected transaction failures.

---

### Transfer Reverts Due to Delegation Owner Clearing

**Severity:** Low  

**Affected Contract(s):**
- `VotingEscrow`

**Affected Function(s):**
- `_transferFrom`

**Description:**

In the transfer flow, ownership of a token is cleared (idToOwner set to address(0)) before delegating vote checkpoints. The delegation library then iterates over token IDs and calls the passed-in ownerOf function on each, including the just-transferred token. Since ownerOf reverts for tokens with no owner, the delegation step always fails and the entire transfer is reverted.

**Root Cause:**

Ownership is removed (`_removeTokenFrom`) before calling moveTokenDelegates, and moveTokenDelegates calls ownerOf on the cleared token, triggering a revert when idToOwner[tokenId] == address(0).

**Impact:**

All token transfers will revert unconditionally, preventing any ERC-721 transfers and effectively locking the entire token contract.

---

### Zero-Amount Locked NFTs in multiSplit

**Severity:** Low  

**Affected Contract(s):**
- `VotingEscrow`

**Affected Function(s):**
- `_createSplitNFT`

**Description:**

The multiSplit function computes each split’s amount using integer division, which can result in newLocked.amount being zero when the original lock amount is too small relative to the weight distribution. Since `_createSplitNFT` writes the provided LockedBalance directly into storage and mints an NFT without validating that amount is positive or end timestamp is in the future, it allows creation of zero-balance NFTs.

**Root Cause:**

Missing validation on the `_newLocked` struct: neither multiSplit nor `_createSplitNFT` enforces that newLocked.amount > 0 before writing to storage and minting.

**Impact:**

Attackers or users can generate NFTs with zero voting power, breaking protocol invariants, wasting gas, potentially leading to denial-of-service or unpredictable behavior in downstream logic that assumes non-zero locks.

---

### Lock Expiration Blocks Future Deposits and Penalty Rewards

**Severity:** Low  

**Affected Contract(s):**
- `GrowthHYBR`

**Affected Function(s):**
- `deposit, receivePenaltyReward`

**Description:**

Both the deposit and receivePenaltyReward functions only mint a new veNFT when `veTokenId == 0`. Once a lock expires, any attempt to add to it via `deposit_for` reverts in the VotingEscrow (`require(_locked.end > block.timestamp)`). Because GrowthHYBR never resets `veTokenId` to zero after expiration, it can neither mint a fresh lock nor accept penalty rewards, effectively disabling deposits and penalty reward operations forever.

**Root Cause:**

Missing logic to detect and handle expiration of the veNFT lock; `veTokenId` remains non-zero after expiration, preventing new lock creation.

**Impact:**

After the veNFT lock expires, the protocol can no longer accept deposits or penalty rewards, freezing user funds and disrupting protocol operations until the contract is redeployed or upgraded. 

---

### Poke Function Bypasses maxVotingNum Restriction

**Severity:** Low  

**Affected Contract(s):**
- `VoterV3`

**Affected Function(s):**
- `poke`

**Description:**

The poke function reads the stored `poolVote[_tokenId]` array and forwards it to the internal `_vote` call without validating that its length does not exceed the current maxVotingNum. If governance lowers maxVotingNum after a user has voted on more pools, calling poke will still process all previously voted pools, effectively bypassing the new limit.

**Root Cause:**

poke reuses an unbounded poolVote array and neither poke nor `_vote` enforce a require(poolVote.length <= maxVotingNum) check.

**Impact:**

Users can cast votes on more pools than permitted by the updated maxVotingNum, manipulating gauge weight distributions, bribe mechanics, and overall protocol governance beyond the intended cap.

---

### Zero-weight Vote Burns Voting Rights

**Severity:** Low  

**Affected Contract(s):**
- `VoterV3`

**Affected Function(s):**
- `vote (and internal _vote)`

**Description:**

When a user calls `vote` with only inactive pools, the internal `_vote` loop is skipped entirely because `gaugeManager.isGaugeAliveForPool` returns false for each pool. No `require` is triggered, so `_usedWeight` remains zero. After returning from `_vote`, the parent `vote` function unconditionally updates `lastVoted[_tokenId]`, preventing any further votes in the same epoch, effectively burning the user’s voting rights without allocating any weight.

**Root Cause:**

Missing validation to ensure that at least one pool receives non-zero weight before marking the token as voted. There is no `require(_usedWeight > 0)` guard in `vote` or `_vote`.

**Impact:**

A user (or attacker) can inadvertently—or deliberately—lose all voting power for the current epoch by submitting only inactive pools. Once called, `lastVoted` is updated and no further votes can be cast until the next epoch.

---

### Unbounded Loop Gas DOS in increaseObservationCardinalityNext

**Severity:** Low  

**Affected Contract(s):**
- `CLPool`

**Affected Function(s):**
- `increaseObservationCardinalityNext`

**Description:**

The function takes a user-supplied uint16 `observationCardinalityNext` and calls `Oracle.grow` with it. `Oracle.grow` loops from the old cardinality up to the new target, performing one SSTORE per iteration with no upper bound on the number of iterations (aside from uint16 max). A malicious caller can request a very large target (up to 65,535) and force hundreds or tens of thousands of SSTOREs, causing excessive gas usage or out-of-gas reverts.

**Root Cause:**

Lack of validation or hard cap on the `observationCardinalityNext` parameter in `increaseObservationCardinalityNext`, combined with an unbounded storage-writing loop in `Oracle.grow`.

**Impact:**

An attacker can drive extremely high gas consumption or intentionally exceed the block gas limit, resulting in denial-of-service (transactions revert) or forcing callers to incur exorbitant gas costs.

---

### Mint Function Skips Deposit Verification for Zero Token Deltas

**Severity:** Low  

**Affected Contract(s):**
- `CLPool`

**Affected Function(s):**
- `mint`

**Description:**

When minting liquidity entirely above the current price with a very small liquidityDelta, `_modifyPosition` returns amount0 = 0 and amount1 = 0. The mint function only takes balance snapshots and enforces token transfers when either amount0 or amount1 is positive. If both are zero, the snapshot and require checks are skipped, yet the pool’s internal liquidity is still increased. An attacker can thus mint positive liquidity without depositing any tokens.

**Root Cause:**

Conditional checks for token deposits are only applied when amount0 > 0 or amount1 > 0, allowing both checks to be bypassed when both deltas are zero.

**Impact:**

An attacker can acquire free liquidity, inflating their share of the pool and potentially draining fees or manipulating price, undermining the pool’s integrity and leading to economic loss.


---

### CollectFees Fails to Enforce Minimum Buffer of 1 on Initial Zero or One Balances

**Severity:** Low  

**Affected Contract(s):**
- `CLPool`

**Affected Function(s):**
- `collectFees`

**Description:**

The collectFees function reads accumulated gauge fees (token0 and token1), transfers out any amount exceeding 1 back to the gauge, and resets the stored fee balance to 1. However, if gaugeFees.token0 or token1 is initially 0 or exactly 1, the function’s conditional checks (`if (amountX > 1)`) never trigger. As a result, the stored fee remains at 0 or 1, violating the invariant that at least one unit must always remain in gaugeFees.

**Root Cause:**

GaugeFees struct is default‐initialized to zero, and the collectFees logic only resets balances when the pre‐collect amount exceeds 1. There is no branch to handle initial values of 0 or 1, so those states persist unmodified.

**Impact:**

A malicious or misconfigured gauge can call collectFees before any fees accrue, leaving gaugeFees.token0 or token1 at zero. Downstream logic (e.g., fee accounting or NFT reward calculations) that assumes a minimum buffer of 1 may malfunction or be bypassed, potentially disrupting fee distribution or causing arithmetic errors.

---

### Off-by-One Error Locks Residual Tokens in CLPool

**Severity:** Low  

**Affected Contract(s):**
- `CLPool`

**Affected Function(s):**
- `collectFees, collectProtocolFees`

**Description:**

Both collectFees and collectProtocolFees introduce an off-by-one error when transferring token1 (and token0 analogously), leaving a single smallest unit permanently stranded. In collectFees, gaugeFees.token1 is reset to 1 then --amount1 is transferred, leaving gaugeFees.token1 at 1 which never meets the >1 threshold on subsequent calls. In collectProtocolFees, protocolFees.token1=1 is reset to 0, then --amount1 transfers 0, removing the record but leaving the one unit in the contract with no withdrawal path.

**Root Cause:**

Sentinel-value logic combined with pre-decrement transfers causes one unit to be left uncredited in fee mappings and untransferable.

**Impact:**

One unit of each token may become permanently locked in the pool, reducing withdrawable balances for the gauge or protocol and causing loss of funds.

---

### Unbounded Iteration Gas Exhaustion in collectAllProtocolFees

**Severity:** Low  

**Affected Contract(s):**
- `CLFactory`

**Affected Function(s):**
- `collectAllProtocolFees`

**Description:**

The function loops over the entire allPools array in a single transaction without any cap or pagination. As the array grows unbounded, the gas required for this loop eventually exceeds block or transaction gas limits, causing the call to revert and preventing fee collection.

**Root Cause:**

Unbounded iteration over a dynamically growing array with no batching, limits, or exit strategy.

**Impact:**

Denial-of-Service on protocol fee collection: once allPools grows beyond a certain size, the owner can no longer collect fees, locking protocol revenue.

---

### Public receivePenaltyReward Enables Unauthorized Token Locking and Liquidity Denial-of-Service

**Severity:** Low  

**Affected Contract(s):**
- `GrowthHYBR`

**Affected Function(s):**
- `receivePenaltyReward`

**Description:**

The receivePenaltyReward function is declared external with no access control. Any user who first deposits HYBR into the contract can call receivePenaltyReward(amount) to approve and lock those tokens into the voting escrow NFT and extend its lock duration. Because no guard restricts this action to the operator or owner, arbitrary callers can repeatedly lock up the contract’s HYBR balance, starving free liquidity.

**Root Cause:**

Missing access control modifier on receivePenaltyReward allows any address to invoke the function.

**Impact:**

An attacker can lock up contract-held HYBR tokens in the voting escrow for the maximum term, reducing the free HYBR balance and preventing gHYBR holders from redeeming their underlying tokens. This creates a denial-of-service condition for withdrawals, potentially freezing redemptions indefinitely.

---

### EmergencyWithdraw Omits Rewarder Notifications

**Severity:** Low  

**Affected Contract(s):**
- `GaugeV2`

**Affected Function(s):**
- `emergencyWithdraw`

**Description:**

The `emergencyWithdraw` function bypasses the standard reward‐sync and external rewarder hooks present in the normal `_withdraw` flow. It directly zeroes the user’s balance and transfers tokens without calling the `updateReward` modifier or invoking `IRewarder(gaugeRewarder).onReward(...)`. As a result, any secondary rewarder contract remains unaware that the user has withdrawn, leading to stale accounting and missed or misallocated rewards.

**Root Cause:**

`emergencyWithdraw` fails to call the reward synchronization logic (the `updateReward` modifier) and omits the `gaugeRewarder.onReward` hook that the regular `_withdraw` path uses to inform external rewarder contracts of balance changes.

**Impact:**

External incentive managers will have stale user balances, causing users to lose unclaimed secondary rewards or enabling incorrect reward distributions. This can undermine the integrity of reward programs and lead to financial losses for users.

---

### abstain() Fails to Detach Token, Retaining Voting Weight

**Severity:** Low  

**Affected Contract(s):**
- `VotingEscrow`

**Affected Function(s):**
- `abstain`

**Description:**

The `abstain()` function only resets the `voted[_tokenId]` flag to false but does not call `detach()` or otherwise decrement the `attachments[_tokenId]` counter. As a result, once a token has voted, its attachment count remains positive, so it stays marked as “attached” and continues to contribute voting power in global tallies even after abstaining.

**Root Cause:**

`abstain()` omits any call to `detach()` or similar logic to decrement the `attachments` mapping and notify gauges, leaving the token’s attachment count and voting weight unchanged.

**Impact:**

Tokens remain locked and their voting power persists indefinitely after abstaining, leading to incorrect or inflated governance results and preventing legitimate withdrawal, splitting, or merging of the token.

---

### Token-Based Voting Lock Carries Over on Transfer

**Severity:** Low  

**Affected Contract(s):**
- `VoterV3`

**Affected Function(s):**
- `vote / onlyNewEpoch`

**Description:**

In VoterV3 the mapping lastVoted[tokenId] records the epoch index when a token last cast a vote. This mapping is never cleared upon NFT transfers. The onlyNewEpoch modifier blocks any vote if lastVoted[tokenId] is greater than or equal to the current epoch start. As a result, if the previous owner votes mid-epoch (setting lastVoted to the current epoch), then transfers the token, the new owner is unable to vote until the next epoch despite not having voted themselves.

**Root Cause:**

Using a tokenId‐keyed lastVoted mapping without resetting it on ownership transfer causes stale state to persist across owners.

**Impact:**

New token owners can be unfairly prevented from voting for the remainder of the current epoch, effectively denying their voting rights until the next epoch.

---

### Unbounded Nested Loops Leading to Gas Exhaustion

**Severity:** Low  

**Affected Contract(s):**
- `GrowthHYBR`

**Affected Function(s):**
- `claimRewards`

**Description:**

The claimRewards function iterates over every pool returned by IVoter.poolVote and, for each pool, loops over all bribe tokens returned by IBribe.rewardsListLength/bribeTokens without any bounds or batching. Because both the number of pools and the number of tokens per bribe are unbounded, the total gas cost grows as O(#pools × #tokens) and can exceed the block gas limit, causing the transaction to revert.

**Root Cause:**

Unbounded nested loops over dynamic arrays (votedPools and bribeTokens) with no limits, batching, or safeguards in GrowthHYBR or downstream calls.

**Impact:**

An attacker or maliciously large data in IVoter or Bribe contracts can force claimRewards to consume excessive gas and revert, resulting in a denial-of-service that prevents reward claims.

---

### Missing Zero-Address Validation in setInternalBribe

**Severity:** Low  

**Affected Contract(s):**
- `GaugeFactoryCL`

**Affected Function(s):**
- `setInternalBribe`

**Description:**

The function uses `require(_int >= address(0))`, which always passes (even for the zero address). This allows the owner to set `internal_bribe` to `address(0)`. When fees are claimed later, the contract attempts to call `safeApprove` and `notifyRewardAmount` on the zero address, causing a revert and effectively DoSing the fee-claiming mechanism.

**Root Cause:**

Incorrect use of `>= address(0)` to validate an address, which does not exclude the zero address. The intended check should use `_int != address(0)`.

**Impact:**

If `internal_bribe` is set to the zero address, any subsequent call to `claimFees()` will revert in `_claimFees()`. This blocks all fee distribution, resulting in a denial-of-service against fee claimers.

---

### Stale rHYBR Reference in Deployed Gauges

**Severity:** Low  

**Affected Contract(s):**
- `GaugeFactoryCL`

**Affected Function(s):**
- `createGauge`

**Description:**

The GaugeFactoryCL contract’s setRHYBR function updates the rHYBR token address only for future calls to createGauge. Gauges already deployed via createGauge capture and store the old rHYBR address in their constructor and have no mechanism to update or migrate this value. As a result, deployed GaugeCL instances continue to use an outdated rHYBR contract for reward distribution even after the factory owner changes it.

**Root Cause:**

rHYBR is read only once during GaugeCL instantiation and stored in the gauge’s state; there is no function in GaugeCL or GaugeFactoryCL to propagate an updated rHYBR value to existing gauges.

**Impact:**

Existing gauges will continue sending reward tokens to the outdated rHYBR contract, potentially stranding tokens or splitting liquidity across multiple reward handler contracts. This inconsistency can lead to loss of rewards for users and opens the door to malicious redirections if the factory owner swaps to a malicious rHYBR implementation.

---

### Initialization Omission of Factory Mappings

**Severity:** Low  

**Affected Contract(s):**
- `GaugeManager`

**Affected Function(s):**
- `initialize`

**Description:**

The initialize function pushes provided gauge and pair factory addresses into the `_factoriesData` arrays but never sets the corresponding `isFactory` or `isGaugeFactory` mappings. As a result, the initial factories are not recognized as valid by the contract’s validation logic, leading to inconsistent state and broken functionality for factory management and gauge/pair creation.

**Root Cause:**

The initialize function omits non-zero address checks and fails to assign `isFactory[_factory] = true` and `isGaugeFactory[_gaugeFactory] = true`, unlike the add/replace functions.

**Impact:**

Initial factories remain invalid in the contract’s mappings, preventing removal or replacement of these entries and causing any functionality that checks factory validity (e.g., creating gauges or pairs) to reject legitimate factories. This can lock the contract in an unusable state or disrupt governance and reward distribution.

---

### Missing Partner NFT Check on Destination in merge Function

**Severity:** Low  

**Affected Contract(s):**
- `VotingEscrow`

**Affected Function(s):**
- `merge`

**Description:**

The merge function allows a user to combine a non-partner token into a partner token by only checking the source token against the isPartnerVeNFT mapping. It fails to verify that the destination token is not a partner, enabling unintended merging into partner NFTs and violating the rule that partner NFTs cannot be merged.

**Root Cause:**

The merge function applies the notPartnerNFT modifier only to the `_from` parameter and omits any check on the destination token (`_to`) against the isPartnerVeNFT mapping.

**Impact:**

An attacker can merge non-partner NFTs into partner NFTs, increasing the locked balance and voting power of partner tokens in an unauthorized manner, potentially inflating governance weight or rewards.

---

### Missing Emergency Guard on getReward

**Severity:** Low  

**Affected Contract(s):**
- `GaugeCL`

**Affected Function(s):**
- `getReward`

**Description:**

The getReward function is callable during an emergency state because it lacks the isNotEmergency modifier. A paused (emergency) contract should prevent all state‐changing operations, but getReward can still update internal reward balances, delete entries, approve tokens, and trigger external token operations via `_getReward` and `_updateRewards`.

**Root Cause:**

The isNotEmergency modifier is not applied to getReward, allowing state mutations through `_updateRewards` and `_getReward` even when emergency == true.

**Impact:**

During an emergency pause intended to freeze protocol operations, the DISTRIBUTION contract can still inflate or modify users’ rewards, approve and deposit tokens, and trigger external transfers. This undermines the pause mechanism, potentially enabling unfair reward accumulation and misallocation.

---

### Stale rewardGrowthInside mapping entries cause unbounded storage growth

**Severity:** Low  

**Affected Contract(s):**
- `GaugeCL`

**Affected Function(s):**
- `withdraw`

**Description:**

The withdraw function removes a tokenId from the user’s stakes and transfers the NFT back, but does not clear the associated rewardGrowthInside[tokenId] entry. Since deposit always writes a non-zero snapshot and withdraw never deletes or zeroes it, every unique tokenId ever staked leaves a persistent storage slot. Over time, as new tokenIds are used, the mapping grows without bound, inflating storage usage and gas costs.

**Root Cause:**

The withdraw function omits any deletion or reset of the rewardGrowthInside mapping entry for the withdrawn tokenId, leaving stale non-zero values in storage.

**Impact:**

Unbounded growth of storage slots for each unique tokenId leads to ever-increasing gas costs and can eventually cause transactions to fail or the contract to become unusable (DoS) due to excessive storage bloat.

---

### Stale pendingTeam After acceptTeam

**Severity:** Low  

**Affected Contract(s):**
- `MinterUpgradeable`

**Affected Function(s):**
- `acceptTeam`

**Description:**

The acceptTeam function assigns the pendingTeam to the team role but never clears pendingTeam. As a result, pendingTeam remains set to the previous nominee even after acceptance, which can block or confuse subsequent team-change operations if other functions depend on pendingTeam being zero or correctly reflecting only the current nominee.

**Root Cause:**

acceptTeam does not reset pendingTeam after transferring the team role.

**Impact:**

If proposeTeam (or any function that assigns pendingTeam) requires pendingTeam to be zero before setting a new nominee, stale pendingTeam will permanently block future team changes, potentially locking governance. At minimum, it leads to confusing or incorrect tooling and UI state that still shows an old pending nominee.
