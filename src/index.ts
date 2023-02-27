import {server} from '@passwordless-id/webauthn'
import {AuthenticationEncoded, RegistrationEncoded, RegistrationParsed} from "@passwordless-id/webauthn/src/types"

interface Env {
    Storage: KVNamespace
}

interface UserStorage {
    challenge: string,
    credentials: RegistrationParsed[]
}

interface challengeRequest {
    username: string
}

interface registerRequest {
    username: string,
    registration: RegistrationEncoded
}

interface loginRequest {
    username: string,
    authentication: AuthenticationEncoded
}

function jsonResponse({data = {}, status = 200, headers = {}}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
            'Access-Control-Max-Age': '86400',
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            ...headers,
        },
    })
}

export default {
    async fetch(
        request: Request,
        env: Env,
        ctx: ExecutionContext
    ): Promise<Response> {
        const url = new URL(request.url)
        switch (url.pathname) {
            case '/register/challenge': {
                const data: challengeRequest = await request.json()
                if (!data || !data.username) {
                    return new Response("miss")
                }

                const challenge = crypto.randomUUID()
                const storage: UserStorage = await env.Storage.get(data.username, {type: 'json'}) ?? {
                    challenge: "",
                    credentials: []
                }

                await env.Storage.put(data.username, JSON.stringify({
                    ...storage,
                    challenge
                }))
                return new Response(challenge, {status: 200,})
            }

            case '/register/verify': {
                const data: registerRequest = await request.json()
                if (!data.registration || !data.username) {
                    return new Response("miss")
                }

                const storage: UserStorage = await env.Storage.get(data.registration.username, {type: 'json'})

                if (!storage?.challenge) {
                    return new Response("expired")
                }

                try {
                    const registrationParsed = await server.verifyRegistration(data.registration, {
                        challenge: storage.challenge,
                        origin: new URL(request.url).host,
                    })
                    await env.Storage.put(registrationParsed.credential.id, JSON.stringify({
                            ...storage,
                            credentials: [
                                ...storage.credentials,
                                registrationParsed
                            ]
                        })
                    )
                    return jsonResponse({status: 200})
                } catch (e) {
                    return new Response(JSON.stringify(e))
                }
            }

            case '/login/challenge': {
                const data: challengeRequest = await request.json()
                if (!data || !data.username) {
                    return new Response("miss")
                }
                const storage: UserStorage = await env.Storage.get(data.username, {type: 'json'})
                if (!storage || !storage.credentials || storage.credentials.length == 0) {
                    return jsonResponse({status: 404})
                }
                const challenge = crypto.randomUUID()
                await env.Storage.put(data.username, JSON.stringify({
                    ...storage,
                    challenge
                }))
                return new Response(JSON.stringify({
                    challenge,
                    credentialIds: storage?.credentials.map(
                        (credentialId) => credentialId.credential.id)
                }), {
                    status: 200,
                })
            }

            case '/login/verify': {
                const data: loginRequest = await request.json()
                if (!data.username && !data.authentication) {
                    return new Response("miss")
                }
                const authentication = data.authentication

                const storage: UserStorage = await env.Storage.get(data.username, {type: 'json'})
                if (!storage || !storage.credentials || !storage.challenge) {
                    return new Response("expired")
                }


                /**
                 * 用户当前所用的 Credential
                 */
                const credential = storage.credentials.filter(
                    (credential) => (credential.credential.id == authentication.credentialId)
                )[0]

                const expected = {
                    challenge: storage.challenge,
                    origin: new URL(request.url).host,
                    userVerified: true,
                    counter: credential.authenticator.counter
                }

                try {
                    const authenticationParsed = await server.verifyAuthentication(authentication, credential.credential, expected)
                    /**
                     * 更新认证器的使用次数
                     */
                    // await env.Storage.put(data.username, JSON.stringify({
                    //     ...storage,
                    //     credentials:
                    // }))
                    return jsonResponse({data: authenticationParsed})
                } catch (e) {
                    console.log(e)
                    return new Response(JSON.stringify(e), {status: 500})
                }
            }
        }
        return new Response("Hello World!");
    },
};
