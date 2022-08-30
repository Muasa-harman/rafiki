import axios from 'axios'
import { Counter, IncomingPayment, ResolvedPayment } from '@interledger/pay'

// TODO: we need to fix the typings here. Resolved Payment for ilp-pay is so overloaded
async function resolve(incomingPaymentUrl: URL, gnapToken: string): Promise<ResolvedPayment> {
  // Get Payment Details
  const request = await axios.get(incomingPaymentUrl.toString(), {
    headers: {
      Authorization: `GNAP ${gnapToken}`
    }
  })

  // TODO should we do validation against what is still required from the payment
  const destinationAsset = {
    code: request.data.receivedAmount.assetCode,
    scale: request.data.receivedAmount.assetScale,
  }

  const ilpDetails = {
    address: request.data.ilpStreamConnection.ilpAddress,
    secret: request.data.ilpStreamConnection.sharedSecret
  }

  return {
    destinationAsset: destinationAsset,
    destinationAddress: ilpDetails.address,
    sharedSecret: ilpDetails.secret,
    requestCounter: Counter.from(0)
  }
}

const createHttpUrl = (rawUrl: string, base?: string): URL | undefined => {
  try {
    const url = new URL(rawUrl, base)
    if (url.protocol === 'https:' || url.protocol === 'http:') {
      return url
    }
  } catch (_) {
    return
  }
}
