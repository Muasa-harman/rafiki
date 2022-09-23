import { AccessType, AccessAction } from './grant'
import { AppContext } from '../../app'
import { Transaction } from 'objection'
import { GrantReference } from '../grantReference/model'
import { createVerifier, httpis, RequestLike, verifyContentDigest } from 'http-message-signatures'
import { BinaryLike, KeyLike as CryptoKeyLike, KeyObject, VerifyKeyObjectInput, VerifyPublicKeyInput } from 'crypto'
import { ClientKeys } from '../../clientKeys/model'
import { JWKWithRequired } from 'auth'
import { Request as KoaRequest } from 'koa'

function extractKeyFromJwk(jwk: JWKWithRequired): BinaryLike | CryptoKeyLike | VerifyKeyObjectInput | VerifyPublicKeyInput {
  return KeyObject.from({
    algorithm: {
      name: jwk.alg
    },
    extractable: jwk.ext,
    type: jwk.kty as KeyType,
    usages: jwk.use ? [jwk.use as KeyUsage] : []
  })
}

// Creates a RequestLike object for the http-message-signatures library input
function requestLike(request: KoaRequest): RequestLike {
  return {
    method: request.method,
    headers: request.headers,
    url: request.url
  }
}

async function authenticateClientKeys(clientKeys: ClientKeys, request: KoaRequest): Promise<boolean> {
  const typedRequest = requestLike(request)
  const signatures = httpis.parseSignatures(typedRequest)

  // Ensure the signature uses the required components
  // https://datatracker.ietf.org/doc/html/draft-ietf-gnap-core-protocol#section-7.3.1
  const requiredComponents = [
    '@method',
    '@target-uri',
  ]
  if (request.body) {
    requiredComponents.push('content-digest')

    // Verify the content digest
    verifyContentDigest(typedRequest)
  }
  if (request.headers['authorization']) {
    requiredComponents.push('authorization')
  }


  // Loop through all signatures on the request and verify them
  // TODO - We might want to change this logic to only require one match against the client which is verified
  const verifications: Promise<boolean>[] = []
  signatures.forEach((signature, signatureName) => {

    const { components } = signature
    if (!components || components.length === 0) {
      throw new Error(`No components in signature input parsed for signature '${signatureName}'`)
    }

    requiredComponents.forEach((required) => {
      if (!components.includes(required)) {
        throw new Error(`The signature input is missing the required component '${required}'`)
      }
    })

    const { value: signatureValue, keyid, alg, signatureParams } = signature

    if (!keyid) {
      throw new Error(`The signature input is missing the 'keyid' parameter`)
    }

    if (alg && alg !== 'ed25519') {
      throw new Error(`The signature parameter 'alg' is using an illegal value '${alg}'. Only 'ed25519' is supported.`)
    }

    const jwk = clientKeys.jwk

    // TODO - Load public key from JWK
    const data = Buffer.from(httpis.buildSignedData(typedRequest, components!, signatureParams))

    verifications.push(new Promise<boolean>((resolve, reject) => {
      createVerifier(alg, extractKeyFromJwk(jwk))(data, signatureValue).then((verificationResult) => {
        resolve(verificationResult)
      }).catch((verificationError) => {
        reject(verificationError)
      })
    }))
  })
  const result = (await Promise.all(verifications)).every(result => result)

  return result

}

export function createAuthMiddleware({
  type,
  action
}: {
  type: AccessType
  action: AccessAction
}) {
  return async (
    ctx: AppContext,
    next: () => Promise<unknown>
  ): Promise<void> => {
    const config = await ctx.container.use('config')
    const grantReferenceService = await ctx.container.use(
      'grantReferenceService'
    )
    const logger = await ctx.container.use('logger')
    try {
      const parts = ctx.request.headers.authorization?.split(' ')
      if (parts?.length !== 2 || parts[0] !== 'GNAP') {
        ctx.throw(401, 'Unauthorized')
      }
      const token = parts[1]
      if (
        process.env.NODE_ENV !== 'production' &&
        token === config.devAccessToken
      ) {
        await next()
        return
      }
      const authService = await ctx.container.use('authService')
      const grant = await authService.introspect(token)
      if (!grant || !grant.active) {
        ctx.throw(401, 'Invalid Token')
      }
      if (
        !grant.includesAccess({
          type,
          action,
          identifier: ctx.paymentPointer.url
        })
      ) {
        ctx.throw(403, 'Insufficient Grant')
      }

      let authenticationPassed = false
      try {
        const clientKeysService = await ctx.container.use('clientKeysService')
        const clientKeys = await clientKeysService.getKeyByClientId(grant.clientId)
        authenticationPassed = await authenticateClientKeys(clientKeys, ctx.request)
        if (!authenticationPassed) {
          throw new Error('request is not authentic')
        }
      } catch (err) {
        ctx.throw(401, 'Unauthorized')
      }

      if (authenticationPassed) {
        await GrantReference.transaction(async (trx: Transaction) => {
          const grantRef = await grantReferenceService.get(grant.grant, trx)
          if (grantRef) {
            if (grantRef.clientId !== grant.clientId) {
              logger.debug(
                `clientID ${grant.clientId} for grant ${grant.grant} does not match internal reference clientId ${grantRef.clientId}.`
              )
              ctx.throw(500)
            }
          } else {
            await grantReferenceService.create(
              {
                id: grant.grant,
                clientId: grant.clientId
              },
              trx
            )
          }
        })
        ctx.grant = grant
      }
      await next()
    } catch (err) {
      if (err.status === 401) {
        ctx.status = 401
        ctx.message = err.message
        ctx.set('WWW-Authenticate', `GNAP as_uri=${config.authServerGrantUrl}`)
      } else {
        throw err
      }
    }
  }
}
