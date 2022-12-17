const util = require('./utils');

export const VERRAWSIZE = 6;
export const Versionage = {major: 1, minor: 0};
export const Serialage = {json: '', mgpk: '', cbor: ''};
export const Vstrings = Serialage;
export const Serials = {json: 'JSON', mgpk: 'MGPK', cbor: 'CBOR'};

// # element labels to exclude in digest or signature derivation from inception icp
export const IcpExcludes = ['pre'];
// # element labels to exclude in digest or signature derivation from delegated inception dip
export const DipExcludes = ['pre'];
export const Ilks = {
    icp: 'icp',
    rot: 'rot',
    ixn: 'ixn',
    dip: 'dip',
    drt: 'drt',
    rct: 'rct',
    vrc: 'vrc',
};

export const IcpLabels = ["v", "i", "s", "t", "kt", "k", "n",
    "bt", "b", "c", "a"];

export const DipLabels = ["v", "i", "s", "t", "kt", "k", "n",
    "bt", "b", "c", "a", "di"];

export const RotLabels = ["v", "i", "s", "t", "p", "kt", "k", "n",
    "bt", "br", "ba", "a"]
export const DrtLabels = ["v", "i", "s", "t", "p", "kt", "k", "n",
    "bt", "br", "ba", "a"]
export const IxnLabels = ["v", "i", "s", "t", "p", "a"]

export const KsnLabels = ["v", "i", "s", "t", "p", "d", "f", "dt", "et", "kt", "k", "n",
    "bt", "b", "c", "ee", "di", "r"]

export const RpyLabels = ["v", "t", "d", "dt", "r", "a"]


// let mimes = {
//   json: "application/keri+json",
//   mgpk: "application/keri+msgpack",
//   cbor: "application/keri+cbor",
// };
// let yourNumber = 899
// let hexString =  yourNumber.toString(16);
// let two = '29'.toString(16);
// let three = '39'.toString(16)
// let VERFMT = `KERI${hexString} ${two} ${three}_`   /// version format string
export const VERFULLSIZE = 17;
export const MINSNIFFSIZE = 12 + VERFULLSIZE;
export const MINSIGSIZE = 4;

/**
 * @description  It will return version string
 */
export function versify(version: { major: number, minor: number }, kind = Serials.json, size: number) {
    if (!(Object.values(Serials).indexOf(kind) > -1)) {
        throw new Error('Invalid serialization kind =' + kind);
    }

    if (!version) {
        version = Versionage;
    }

    const hex1 = version.major.toString(16);
    const hex2 = version.minor.toString(16);
    const kindHex = kind;
    const hex3 = util.pad(size.toString(16), VERRAWSIZE);

    return `KERI${hex1}${hex2}${kindHex}${hex3}_`;
}

Vstrings.json = versify(Versionage, Serials.json, 0);
Vstrings.mgpk = versify(Versionage, Serials.mgpk, 0);
Vstrings.cbor = versify(Versionage, Serials.cbor, 0);

// const version_pattern = 'KERI(?P<major>[0-9a-f])(?P<minor>[0-9a-f])
// (?P<kind>[A-Z]{4})(?P<size>[0-9a-f]{6})'
// const version_pattern1 = `KERI\(\?P<major>\[0\-9a\-f\]\)\(\?P<minor>\[0\-9a\-f\]\)\
// (\?P<kind>\[A\-Z\]\{4\}\)\(\?P<size>\[0\-9a\-f\]\{6\}\)_`

export const VEREX = 'KERI([0-9a-f])([0-9a-f])([A-Z]{4})([0-9a-f]{6})';

// Regex pattern matching

/**
 * @description This function is use to deversify the version
 * Here we will use regex to  to validate and extract serialization kind,size and version
 * @param {string} vs   version string
 * @return {Object}  contaning kind of serialization like cbor,json,mgpk
 *                    version = version of object ,size = raw size integer
 */
export function deversify(versionString: string) {
    let kind;
    let size;
    const version = Versionage;

    // we need to identify how to match the buffers pattern ,like we do regex matching for strings
    const re = new RegExp(VEREX);

    const match = re.exec(versionString);

    if (match) {
        [version.major, version.minor, kind, size] = [
            +match[1],
            +match[2],
            match[3],
            match[4],
        ];
        if (!Object.values(Serials).includes(kind)) {
            throw new Error(`Invalid serialization kind = ${kind}`);
        }
        return [kind, version, size];
    }
    throw new Error(`Invalid version string = ${versionString}`);
}

export const B64ChrByIdx = new Map<number, string>([[0, 'A'], [1, 'B'], [2, 'C'], [3, 'D'], [4, 'E'], [5, 'F'],
    [6, 'G'], [7, 'H'], [8, 'I'], [9, 'J'], [10, 'K'], [11, 'L'], [12, 'M'], [13, 'N'], [14, 'O'], [15, 'P'],
    [16, 'Q'], [17, 'R'], [18, 'S'], [19, 'T'], [20, 'U'], [21, 'V'], [22, 'W'], [23, 'X'], [24, 'Y'], [25, 'Z'],
    [26, 'a'], [27, 'b'], [28, 'c'], [29, 'd'], [30, 'e'], [31, 'f'], [32, 'g'], [33, 'h'], [34, 'i'], [35, 'j'],
    [36, 'k'], [37, 'l'], [38, 'm'], [39, 'n'], [40, 'o'], [41, 'p'], [42, 'q'], [43, 'r'], [44, 's'], [45, 't'],
    [46, 'u'], [47, 'v'], [48, 'w'], [49, 'x'], [50, 'y'], [51, 'z'],[ 52, '0'], [53, '1'], [54, '2'], [55, '3'],
    [56, '4'], [57, '5'], [58, '6'], [59, '7'], [60, '8'], [61, '9'], [62, '-'], [63, '_']]);

// TODO: Implement...
export function intToB64(i:number, l=1) {
    console.log(B64ChrByIdx.get(i), l);
    return ""
}

export function readInt(array: Uint8Array) {
    let value = 0;
    for (let i = 0; i < array.length; i++) {
        value = (value * 256) + array[i];
    }
    return value;
}