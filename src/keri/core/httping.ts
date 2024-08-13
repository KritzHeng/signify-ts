import {
    serializeDictionary,
    Dictionary,
    parseDictionary,
    Item,
    Parameters,
} from 'structured-headers';
import { Signer } from './signer';
import { b } from './core';
import { Cigar } from './cigar';
import { nowUTC } from './utils';
import { Siger } from './siger';
import { Buffer } from 'buffer';
import { encodeBase64Url } from './base64';

export const HEADER_SIG_INPUT = normalize('Signature-Input');
export const HEADER_SIG_TIME = normalize('Signify-Timestamp');

export function normalize(header: string) {
    return header.trim();
}

function Uint8ArrayToHex(sig: any): string {
    // Convert the Uint8Array to a hex string
    const hexString = Array.from(sig.raw)
        .map((byte: any) => '\\x' + byte.toString(16).padStart(2, '0'))
        .join('');

    let byteFormat = `b'${hexString}'`;
    return byteFormat;
}

export interface SiginputArgs {
    name: string;
    method: string;
    path: string;
    headers: Headers;
    fields: Array<string>;
    expires?: number;
    nonce?: string;
    alg?: string;
    keyid?: string;
    context?: string;
}

export function siginput(
    signer: Signer,
    {
        name,
        method,
        path,
        headers,
        fields,
        expires,
        nonce,
        alg,
        keyid,
        context,
    }: SiginputArgs
): [Map<string, string>, Siger | Cigar] {
    const items = new Array<string>();
    const ifields = new Array<[string, Map<string, string>]>();

    fields.forEach((field) => {
        if (field.startsWith('@')) {
            switch (field) {
                case '@method':
                    items.push(`"${field}": ${method}`);
                    ifields.push([field, new Map()]);
                    break;
                case '@path':
                    items.push(`"${field}": ${path}`);
                    ifields.push([field, new Map()]);
                    break;
            }
        } else {
            if (!headers.has(field)) return;

            ifields.push([field, new Map()]);
            const value = normalize(headers.get(field)!);
            items.push(`"${field}": ${value}`);
        }
    });

    const nameParams = new Map<string, string | number>();
    const now = Math.floor(nowUTC().getTime() / 1000);
    nameParams.set('created', now);

    const values = [
        `(${ifields.map((field) => field[0]).join(' ')})`,
        `created=${now}`,
    ];
    if (expires != undefined) {
        values.push(`expires=${expires}`);
        nameParams.set('expires', expires);
    }
    if (nonce != undefined) {
        values.push(`nonce=${nonce}`);
        nameParams.set('nonce', nonce);
    }
    if (keyid != undefined) {
        values.push(`keyid=${keyid}`);
        nameParams.set('keyid', keyid);
    }
    if (context != undefined) {
        values.push(`context=${context}`);
        nameParams.set('context', context);
    }
    if (alg != undefined) {
        values.push(`alg=${alg}`);
        nameParams.set('alg', alg);
    }
    const sid = new Map([[name, [ifields, nameParams]]]);

    const params = values.join(';');
    items.push(`"@signature-params: ${params}"`);

    const ser = items.join('\n');
    console.log("ser: ", ser)
    console.log("ser: ", JSON.stringify(ser))
    const sig = signer.sign(b(ser));
    // console.log("ser: ", b(ser))
    // console.log("sig: ", JSON.stringify(sig))
    // console.log("sig: ", sig)
    const sig_hexstring = Uint8ArrayToHex(sig);
    console.log("sig_hexstring: ", sig_hexstring)
    console.log("sig qb64: ", sig.qb64)
    const verfer = signer.verfer;
    console.log("verfer: ", verfer.qb64)
    let verferHexString = Uint8ArrayToHex(verfer);
    console.log("verferHexString: ", verferHexString)
    console.log(`sid: ${serializeDictionary(sid as Dictionary)}`)
    return [
        new Map<string, string>([
            [HEADER_SIG_INPUT, `${serializeDictionary(sid as Dictionary)}`],
        ]),
        sig,
    ];
}

export class Unqualified {
    private readonly _raw: Uint8Array;

    constructor(raw: Uint8Array) {
        this._raw = raw;
    }

    get qb64(): string {
        return encodeBase64Url(Buffer.from(this._raw));
    }

    get qb64b(): Uint8Array {
        return b(this.qb64);
    }
}

export class Inputage {
    public name: any;
    public fields: any;
    public created: any;
    public expires: any;
    public nonce: any;
    public alg: any;
    public keyid: any;
    public context: any;
}

export function desiginput(value: string): Array<Inputage> {
    const sid = parseDictionary(value);
    const siginputs = new Array<Inputage>();

    sid.forEach((value, key) => {
        const siginput = new Inputage();
        siginput.name = key;
        let list: Item[];
        let params;
        [list, params] = value as [Item[], Parameters];
        siginput.fields = list.map((item) => item[0]);

        if (!params.has('created')) {
            throw new Error(
                'missing required `created` field from signature input'
            );
        }
        siginput.created = params.get('created');

        if (params.has('expires')) {
            siginput.expires = params.get('expires');
        }

        if (params.has('nonce')) {
            siginput.nonce = params.get('nonce');
        }

        if (params.has('alg')) {
            siginput.alg = params.get('alg');
        }

        if (params.has('keyid')) {
            siginput.keyid = params.get('keyid');
        }

        if (params.has('context')) {
            siginput.context = params.get('context');
        }

        siginputs.push(siginput);
    });

    return siginputs;
}
/** Parse start, end and total from HTTP Content-Range header value
 * @param {string|null} header - HTTP Range header value
 * @param {string} typ - type of range, e.g. "aids"
 * @returns {start: number, end: number, total: number} - object with start, end and total properties
 */
export function parseRangeHeaders(
    header: string | null,
    typ: string
): { start: number; end: number; total: number } {
    if (header !== null) {
        const data = header.replace(`${typ} `, '');
        const values = data.split('/');
        const rng = values[0].split('-');

        return {
            start: parseInt(rng[0]),
            end: parseInt(rng[1]),
            total: parseInt(values[1]),
        };
    } else {
        return { start: 0, end: 0, total: 0 };
    }
}
