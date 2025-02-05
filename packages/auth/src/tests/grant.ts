import { faker } from '@faker-js/faker'
import { FinishMethod, Grant, StartMethod } from '../grant/model'
import { generateNonce } from '../shared/utils'
import { AccessAction, AccessType } from '@interledger/open-payments'
import { IocContract } from '@adonisjs/fold'
import { AppServices } from '../app'

export async function createGrant(
  deps: IocContract<AppServices>,
  options?: { identifier?: string }
): Promise<Grant> {
  const grantService = await deps.use('grantService')
  const CLIENT = faker.internet.url({ appendSlash: false })
  const BASE_GRANT_ACCESS = {
    actions: [AccessAction.Create, AccessAction.Read, AccessAction.List],
    identifier: options?.identifier
  }

  const BASE_GRANT_REQUEST = {
    client: CLIENT,
    interact: {
      start: [StartMethod.Redirect],
      finish: {
        method: FinishMethod.Redirect,
        uri: 'https://example.com/finish',
        nonce: generateNonce()
      }
    }
  }

  return await grantService.create({
    ...BASE_GRANT_REQUEST,
    access_token: {
      access: [
        {
          ...BASE_GRANT_ACCESS,
          type: AccessType.IncomingPayment
        }
      ]
    }
  })
}
