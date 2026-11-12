import {
  BrowserProvider,
  Contract
} from 'ethers'

export const SEPOLIA_CHAIN_ID = 11155111n
export const SEPOLIA_CHAIN_HEX = '0xaa36a7'

const CONTRACT_ADDRESS = import.meta.env.VITE_ETHEREUM_CONTRACT_ADDRESS || ''

export const MEDIQUEUE_ANCHOR_ABI = [
  'function owner() view returns (address)',
  'function totalAnchors() view returns (uint256)',
  'function anchored(bytes32) view returns (bool)',
  'function anchorBatch(bytes32[] blockHashes, uint256[] localIndexes, string[] eventTypes)',
  'event BlockAnchored(bytes32 indexed blockHash, uint256 indexed localIndex, string eventType, address indexed anchoredBy, uint256 timestamp)'
]

function requireWallet() {
  if (!window.ethereum) {
    throw new Error('MetaMask was not detected. Install the MetaMask browser extension and refresh this page.')
  }
}

function requireContractAddress() {
  if (!/^0x[a-fA-F0-9]{40}$/.test(CONTRACT_ADDRESS)) {
    throw new Error('Ethereum contract address is missing or invalid. Deploy contracts/MediQueueAnchor.sol, then set VITE_ETHEREUM_CONTRACT_ADDRESS in your .env file and restart Vite.')
  }
}

async function switchToSepolia(provider) {
  let network = await provider.getNetwork()
  if (network.chainId === SEPOLIA_CHAIN_ID) return provider

  try {
    await provider.send('wallet_switchEthereumChain', [
      { chainId: SEPOLIA_CHAIN_HEX }
    ])
  } catch (error) {
    if (error.code !== 4902) {
      throw new Error('Please approve switching MetaMask to Ethereum Sepolia.')
    }

    await provider.send('wallet_addEthereumChain', [{
      chainId: SEPOLIA_CHAIN_HEX,
      chainName: 'Sepolia',
      nativeCurrency: {
        name: 'Sepolia Ether',
        symbol: 'ETH',
        decimals: 18
      },
      rpcUrls: ['https://ethereum-sepolia-rpc.publicnode.com'],
      blockExplorerUrls: ['https://sepolia.etherscan.io']
    }])
  }

  const updatedProvider = new BrowserProvider(window.ethereum)
  network = await updatedProvider.getNetwork()

  if (network.chainId !== SEPOLIA_CHAIN_ID) {
    throw new Error('MetaMask is not connected to Ethereum Sepolia.')
  }

  return updatedProvider
}

function contractAt(providerOrSigner) {
  requireContractAddress()
  return new Contract(CONTRACT_ADDRESS, MEDIQUEUE_ANCHOR_ABI, providerOrSigner)
}

export async function connectSepoliaWallet() {
  requireWallet()
  requireContractAddress()

  let provider = new BrowserProvider(window.ethereum)
  await provider.send('eth_requestAccounts', [])
  provider = await switchToSepolia(provider)

  const signer = await provider.getSigner()
  const account = await signer.getAddress()
  const contract = contractAt(signer)
  const [totalAnchors, owner] = await Promise.all([
    contract.totalAnchors(),
    contract.owner()
  ])

  return {
    provider,
    account,
    owner,
    totalAnchors: Number(totalAnchors),
    isOwner: account.toLowerCase() === owner.toLowerCase()
  }
}

export async function readSepoliaAnchorStatus(provider, blocks) {
  const contract = contractAt(provider)
  const totalAnchors = Number(await contract.totalAnchors())
  const relevant = blocks.filter(block => block.index > 0 && /^[a-fA-F0-9]{64}$/.test(block.hash))

  const statuses = {}
  // Keep RPC requests in small batches to avoid overwhelming public endpoints.
  for (let i = 0; i < relevant.length; i += 10) {
    const batch = relevant.slice(i, i + 10)
    const results = await Promise.all(
      batch.map(block => contract.anchored(`0x${block.hash}`))
    )
    batch.forEach((block, index) => {
      statuses[block.hash] = Boolean(results[index])
    })
  }

  return { totalAnchors, statuses }
}

export async function anchorPendingBlocks(provider, blocks) {
  const signer = await provider.getSigner()
  const contract = contractAt(signer)
  const validBlocks = blocks
    .filter(block => block.index > 0 && /^[a-fA-F0-9]{64}$/.test(block.hash))
    .slice(0, 10)

  if (!validBlocks.length) {
    throw new Error('There are no pending local blocks to anchor.')
  }

  const hashes = validBlocks.map(block => `0x${block.hash}`)
  const indexes = validBlocks.map(block => BigInt(block.index))
  const eventTypes = validBlocks.map(block => String(block.type).slice(0, 80))

  const transaction = await contract.anchorBatch(hashes, indexes, eventTypes)
  const receipt = await transaction.wait()

  return {
    transactionHash: transaction.hash,
    blockNumber: Number(receipt.blockNumber),
    anchoredCount: validBlocks.length
  }
}

export const getSepoliaContractAddress = () => CONTRACT_ADDRESS
