import { PaymentPointerContext } from '../../app'
import { ClientService } from '../../clients/service'
import { IAppConfig } from '../../config/app'

interface ServiceDependencies {
  config: IAppConfig,
  clientService: ClientService,
}

export interface PaymentPointerRoutes {
  get(ctx: PaymentPointerContext): Promise<void>,
  getJwks(ctx: PaymentPointerContext): Promise<void>
}

export function createPaymentPointerRoutes(
  deps: ServiceDependencies
): PaymentPointerRoutes {
  return {
    get: (ctx: PaymentPointerContext) => getPaymentPointer(deps, ctx),
    getJwks: (ctx: PaymentPointerContext) => getJwks(deps, ctx)
  }
}

// Spec: https://docs.openpayments.guide/reference/get-public-account
export async function getPaymentPointer(
  deps: ServiceDependencies,
  ctx: PaymentPointerContext
): Promise<void> {
  if (!ctx.paymentPointer) {
    return ctx.throw(404)
  }

  ctx.body = {
    id: ctx.paymentPointer.url,
    publicName: ctx.paymentPointer.publicName ?? undefined,
    assetCode: ctx.paymentPointer.asset.code,
    assetScale: ctx.paymentPointer.asset.scale,
    authServer: deps.config.authServerGrantUrl
  }
}

export async function getJwks(
  deps: ServiceDependencies,
  ctx: PaymentPointerContext
): Promise<void> {
  if (!ctx.paymentPointer) {
    return ctx.throw(404)
  }

  const client = await deps.clientService.getClient(ctx.paymentPointer.id)

  // return jwk set
  ctx.body = {
    keys: client.keys.map((key) => key.jwk)
  }
}
