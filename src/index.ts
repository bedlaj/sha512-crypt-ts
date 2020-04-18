class Int64 {
    h: any;
    l: any;

    constructor(h: any, l: any) {
        this.h = h;
        this.l = l;
    }
}

class Delegate {

    /**
     * hex output format. 0 - lowercase; 1 - uppercase
     */
    hexcase: number = 0;
    /**
     * base-64 pad character. "=" for strict RFC compliance
     */
    b64pad: string = "";

    /**
     * Calculate the SHA-512 of a raw string
     */
    public rstr_sha512(s: any) {
        return Delegate.binb2rstr(this.binb_sha512(Delegate.rstr2binb(s), s.length * 8));
    }

    /**
     * Calculate the HMAC-SHA-512 of a key and some data (raw strings)
     */
    public rstr_hmac_sha512(key: any, data: any) {
        let bkey = Delegate.rstr2binb(key);
        if (bkey.length > 32) bkey = this.binb_sha512(bkey, key.length * 8);

        const ipad = Array(32), opad = Array(32);
        for (let i = 0; i < 32; i++) {
            ipad[i] = bkey[i] ^ 0x36363636;
            opad[i] = bkey[i] ^ 0x5C5C5C5C;
        }

        const hash = this.binb_sha512(ipad.concat(Delegate.rstr2binb(data)), 1024 + data.length * 8);
        return Delegate.binb2rstr(this.binb_sha512(opad.concat(hash), 1024 + 512));
    }

    /**
     * Convert a raw string to a hex string
     */
    public rstr2hex(input: any) {
        const hex_tab = this.hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
        let output = "";
        let x;
        for (let i = 0; i < input.length; i++) {
            x = input.charCodeAt(i);
            output += hex_tab.charAt((x >>> 4) & 0x0F)
                + hex_tab.charAt(x & 0x0F);
        }
        return output;
    }

    /**
     * Convert a raw string to a base-64 string
     */
    public rstr2b64(input: any) {
        const tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let output = "";
        const len = input.length;
        for (let i = 0; i < len; i += 3) {
            const triplet = (input.charCodeAt(i) << 16)
                | (i + 1 < len ? input.charCodeAt(i + 1) << 8 : 0)
                | (i + 2 < len ? input.charCodeAt(i + 2) : 0);
            for (let j = 0; j < 4; j++) {
                if (i * 8 + j * 6 > input.length * 8) output += this.b64pad;
                else output += tab.charAt((triplet >>> 6 * (3 - j)) & 0x3F);
            }
        }
        return output;
    }

    /**
     * Convert a raw string to an arbitrary string encoding
     */
    public rstr2any(input: any, encoding: any) {
        const divisor = encoding.length;
        let i, j, q, x, quotient;

        /* Convert to an array of 16-bit big-endian values, forming the dividend */
        let dividend = Array(Math.ceil(input.length / 2));
        for (i = 0; i < dividend.length; i++) {
            dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
        }

        /*
         * Repeatedly perform a long division. The binary array forms the dividend,
         * the length of the encoding is the divisor. Once computed, the quotient
         * forms the dividend for the next step. All remainders are stored for later
         * use.
         */
        const full_length = Math.ceil(input.length * 8 /
            (Math.log(encoding.length) / Math.log(2)));
        const remainders = Array(full_length);
        for (j = 0; j < full_length; j++) {
            quotient = Array();
            x = 0;
            for (i = 0; i < dividend.length; i++) {
                x = (x << 16) + dividend[i];
                q = Math.floor(x / divisor);
                x -= q * divisor;
                if (quotient.length > 0 || q > 0)
                    quotient[quotient.length] = q;
            }
            remainders[j] = x;
            dividend = quotient;
        }

        /* Convert the remainders to the output string */
        let output = "";
        for (i = remainders.length - 1; i >= 0; i--)
            output += encoding.charAt(remainders[i]);

        return output;
    }

    /**
     * Encode a string as utf-8.
     * For efficiency, this assumes the input is valid utf-16.
     */
    public str2rstr_utf8(input: any) {
        let output = "";
        let i = -1;
        let x, y;

        while (++i < input.length) {
            /* Decode utf-16 surrogate pairs */
            x = input.charCodeAt(i);
            y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
            if (0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF) {
                x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
                i++;
            }

            /* Encode output as utf-8 */
            if (x <= 0x7F)
                output += String.fromCharCode(x);
            else if (x <= 0x7FF)
                output += String.fromCharCode(0xC0 | ((x >>> 6) & 0x1F),
                    0x80 | (x & 0x3F));
            else if (x <= 0xFFFF)
                output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                    0x80 | ((x >>> 6) & 0x3F),
                    0x80 | (x & 0x3F));
            else if (x <= 0x1FFFFF)
                output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                    0x80 | ((x >>> 12) & 0x3F),
                    0x80 | ((x >>> 6) & 0x3F),
                    0x80 | (x & 0x3F));
        }
        return output;
    }

    /**
     * Convert a raw string to an array of big-endian words
     * Characters >255 have their high-byte silently ignored.
     */
    private static rstr2binb(input: any) {
        const output = Array(input.length >> 2);
        for (let i = 0; i < output.length; i++)
            output[i] = 0;
        for (let i = 0; i < input.length * 8; i += 8)
            output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
        return output;
    }

    /**
     * Convert an array of big-endian words to a string
     */
    private static binb2rstr(input: any) {
        let output = "";
        for (let i = 0; i < input.length * 32; i += 8)
            output += String.fromCharCode((input[i >> 5] >>> (24 - i % 32)) & 0xFF);
        return output;
    }

    /**
     * Calculate the SHA-512 of an array of big-endian dwords, and a bit length
     */
    sha512_k: any = undefined;

    private binb_sha512(x: any, len: any) {
        if (this.sha512_k == undefined) {
            //SHA512 constants
            this.sha512_k = [new Int64(0x428a2f98, -685199838), new Int64(0x71374491, 0x23ef65cd),
                new Int64(-1245643825, -330482897), new Int64(-373957723, -2121671748),
                new Int64(0x3956c25b, -213338824), new Int64(0x59f111f1, -1241133031),
                new Int64(-1841331548, -1357295717), new Int64(-1424204075, -630357736),
                new Int64(-670586216, -1560083902), new Int64(0x12835b01, 0x45706fbe),
                new Int64(0x243185be, 0x4ee4b28c), new Int64(0x550c7dc3, -704662302),
                new Int64(0x72be5d74, -226784913), new Int64(-2132889090, 0x3b1696b1),
                new Int64(-1680079193, 0x25c71235), new Int64(-1046744716, -815192428),
                new Int64(-459576895, -1628353838), new Int64(-272742522, 0x384f25e3),
                new Int64(0xfc19dc6, -1953704523), new Int64(0x240ca1cc, 0x77ac9c65),
                new Int64(0x2de92c6f, 0x592b0275), new Int64(0x4a7484aa, 0x6ea6e483),
                new Int64(0x5cb0a9dc, -1119749164), new Int64(0x76f988da, -2096016459),
                new Int64(-1740746414, -295247957), new Int64(-1473132947, 0x2db43210),
                new Int64(-1341970488, -1728372417), new Int64(-1084653625, -1091629340),
                new Int64(-958395405, 0x3da88fc2), new Int64(-710438585, -1828018395),
                new Int64(0x6ca6351, -536640913), new Int64(0x14292967, 0xa0e6e70),
                new Int64(0x27b70a85, 0x46d22ffc), new Int64(0x2e1b2138, 0x5c26c926),
                new Int64(0x4d2c6dfc, 0x5ac42aed), new Int64(0x53380d13, -1651133473),
                new Int64(0x650a7354, -1951439906), new Int64(0x766a0abb, 0x3c77b2a8),
                new Int64(-2117940946, 0x47edaee6), new Int64(-1838011259, 0x1482353b),
                new Int64(-1564481375, 0x4cf10364), new Int64(-1474664885, -1136513023),
                new Int64(-1035236496, -789014639), new Int64(-949202525, 0x654be30),
                new Int64(-778901479, -688958952), new Int64(-694614492, 0x5565a910),
                new Int64(-200395387, 0x5771202a), new Int64(0x106aa070, 0x32bbd1b8),
                new Int64(0x19a4c116, -1194143544), new Int64(0x1e376c08, 0x5141ab53),
                new Int64(0x2748774c, -544281703), new Int64(0x34b0bcb5, -509917016),
                new Int64(0x391c0cb3, -976659869), new Int64(0x4ed8aa4a, -482243893),
                new Int64(0x5b9cca4f, 0x7763e373), new Int64(0x682e6ff3, -692930397),
                new Int64(0x748f82ee, 0x5defb2fc), new Int64(0x78a5636f, 0x43172f60),
                new Int64(-2067236844, -1578062990), new Int64(-1933114872, 0x1a6439ec),
                new Int64(-1866530822, 0x23631e28), new Int64(-1538233109, -561857047),
                new Int64(-1090935817, -1295615723), new Int64(-965641998, -479046869),
                new Int64(-903397682, -366583396), new Int64(-779700025, 0x21c0c207),
                new Int64(-354779690, -840897762), new Int64(-176337025, -294727304),
                new Int64(0x6f067aa, 0x72176fba), new Int64(0xa637dc5, -1563912026),
                new Int64(0x113f9804, -1090974290), new Int64(0x1b710b35, 0x131c471b),
                new Int64(0x28db77f5, 0x23047d84), new Int64(0x32caab7b, 0x40c72493),
                new Int64(0x3c9ebe0a, 0x15c9bebc), new Int64(0x431d67c4, -1676669620),
                new Int64(0x4cc5d4be, -885112138), new Int64(0x597f299c, -60457430),
                new Int64(0x5fcb6fab, 0x3ad6faec), new Int64(0x6c44198c, 0x4a475817)];
        }

        //Initial hash values
        const H = [new Int64(0x6a09e667, -205731576),
            new Int64(-1150833019, -2067093701),
            new Int64(0x3c6ef372, -23791573),
            new Int64(-1521486534, 0x5f1d36f1),
            new Int64(0x510e527f, -1377402159),
            new Int64(-1694144372, 0x2b3e6c1f),
            new Int64(0x1f83d9ab, -79577749),
            new Int64(0x5be0cd19, 0x137e2179)];

        const T1 = new Int64(0, 0),
            T2 = new Int64(0, 0),
            a = new Int64(0, 0),
            b = new Int64(0, 0),
            c = new Int64(0, 0),
            d = new Int64(0, 0),
            e = new Int64(0, 0),
            f = new Int64(0, 0),
            g = new Int64(0, 0),
            h = new Int64(0, 0),
            //Temporary variables not specified by the document
            s0 = new Int64(0, 0),
            s1 = new Int64(0, 0),
            Ch = new Int64(0, 0),
            Maj = new Int64(0, 0),
            r1 = new Int64(0, 0),
            r2 = new Int64(0, 0),
            r3 = new Int64(0, 0);
        let j, i;
        const W = new Array(80);
        for (i = 0; i < 80; i++)
            W[i] = new Int64(0, 0);

        // append padding to the source string. The format is described in the FIPS.
        x[len >> 5] |= 0x80 << (24 - (len & 0x1f));
        x[((len + 128 >> 10) << 5) + 31] = len;

        for (i = 0; i < x.length; i += 32) //32 dwords is the block size
        {
            Delegate.int64copy(a, H[0]);
            Delegate.int64copy(b, H[1]);
            Delegate.int64copy(c, H[2]);
            Delegate.int64copy(d, H[3]);
            Delegate.int64copy(e, H[4]);
            Delegate.int64copy(f, H[5]);
            Delegate.int64copy(g, H[6]);
            Delegate.int64copy(h, H[7]);

            for (j = 0; j < 16; j++) {
                W[j].h = x[i + 2 * j];
                W[j].l = x[i + 2 * j + 1];
            }

            for (j = 16; j < 80; j++) {
                //sigma1
                Delegate.int64rrot(r1, W[j - 2], 19);
                Delegate.int64revrrot(r2, W[j - 2], 29);
                Delegate.int64shr(r3, W[j - 2], 6);
                s1.l = r1.l ^ r2.l ^ r3.l;
                s1.h = r1.h ^ r2.h ^ r3.h;
                //sigma0
                Delegate.int64rrot(r1, W[j - 15], 1);
                Delegate.int64rrot(r2, W[j - 15], 8);
                Delegate.int64shr(r3, W[j - 15], 7);
                s0.l = r1.l ^ r2.l ^ r3.l;
                s0.h = r1.h ^ r2.h ^ r3.h;

                Delegate.int64add4(W[j], s1, W[j - 7], s0, W[j - 16]);
            }

            for (j = 0; j < 80; j++) {
                //Ch
                Ch.l = (e.l & f.l) ^ (~e.l & g.l);
                Ch.h = (e.h & f.h) ^ (~e.h & g.h);

                //Sigma1
                Delegate.int64rrot(r1, e, 14);
                Delegate.int64rrot(r2, e, 18);
                Delegate.int64revrrot(r3, e, 9);
                s1.l = r1.l ^ r2.l ^ r3.l;
                s1.h = r1.h ^ r2.h ^ r3.h;

                //Sigma0
                Delegate.int64rrot(r1, a, 28);
                Delegate.int64revrrot(r2, a, 2);
                Delegate.int64revrrot(r3, a, 7);
                s0.l = r1.l ^ r2.l ^ r3.l;
                s0.h = r1.h ^ r2.h ^ r3.h;

                //Maj
                Maj.l = (a.l & b.l) ^ (a.l & c.l) ^ (b.l & c.l);
                Maj.h = (a.h & b.h) ^ (a.h & c.h) ^ (b.h & c.h);

                Delegate.int64add5(T1, h, s1, Ch, this.sha512_k[j], W[j]);
                Delegate.int64add(T2, s0, Maj);

                Delegate.int64copy(h, g);
                Delegate.int64copy(g, f);
                Delegate.int64copy(f, e);
                Delegate.int64add(e, d, T1);
                Delegate.int64copy(d, c);
                Delegate.int64copy(c, b);
                Delegate.int64copy(b, a);
                Delegate.int64add(a, T1, T2);
            }
            Delegate.int64add(H[0], H[0], a);
            Delegate.int64add(H[1], H[1], b);
            Delegate.int64add(H[2], H[2], c);
            Delegate.int64add(H[3], H[3], d);
            Delegate.int64add(H[4], H[4], e);
            Delegate.int64add(H[5], H[5], f);
            Delegate.int64add(H[6], H[6], g);
            Delegate.int64add(H[7], H[7], h);
        }

        //represent the hash as an array of 32-bit dwords
        const hash = new Array(16);
        for (i = 0; i < 8; i++) {
            hash[2 * i] = H[i].h;
            hash[2 * i + 1] = H[i].l;
        }
        return hash;
    }

    /**
     *  Copies src into dst, assuming both are 64-bit numbers
     */
    private static int64copy(dst: any, src: any) {
        dst.h = src.h;
        dst.l = src.l;
    }

    /**
     * Right-rotates a 64-bit number by shift
     * Won't handle cases of shift>=32
     * The private revrrot() is for that
     * */
    private static int64rrot(dst: any, x: any, shift: any) {
        dst.l = (x.l >>> shift) | (x.h << (32 - shift));
        dst.h = (x.h >>> shift) | (x.l << (32 - shift));
    }

    /**
     * Reverses the dwords of the source and then rotates right by shift.
     * This is equivalent to rotation by 32+shift
     */
    private static int64revrrot(dst: any, x: any, shift: any) {
        dst.l = (x.h >>> shift) | (x.l << (32 - shift));
        dst.h = (x.l >>> shift) | (x.h << (32 - shift));
    }

    /**
     * Bitwise-shifts right a 64-bit number by shift
     * Won't handle shift>=32, but it's never needed in SHA512
     */
    private static int64shr(dst: any, x: any, shift: any) {
        dst.l = (x.l >>> shift) | (x.h << (32 - shift));
        dst.h = (x.h >>> shift);
    }

    /**
     * Adds two 64-bit numbers
     * Like the original implementation, does not rely on 32-bit operations
     */
    private static int64add(dst: any, x: any, y: any) {
        const w0 = (x.l & 0xffff) + (y.l & 0xffff);
        const w1 = (x.l >>> 16) + (y.l >>> 16) + (w0 >>> 16);
        const w2 = (x.h & 0xffff) + (y.h & 0xffff) + (w1 >>> 16);
        const w3 = (x.h >>> 16) + (y.h >>> 16) + (w2 >>> 16);
        dst.l = (w0 & 0xffff) | (w1 << 16);
        dst.h = (w2 & 0xffff) | (w3 << 16);
    }

    /**
     * Adds two 64-bit numbers with 4 addends. Works faster than adding them one by one.
     */
    private static int64add4(dst: any, a: any, b: any, c: any, d: any) {
        const w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff);
        const w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (w0 >>> 16);
        const w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (w1 >>> 16);
        const w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (w2 >>> 16);
        dst.l = (w0 & 0xffff) | (w1 << 16);
        dst.h = (w2 & 0xffff) | (w3 << 16);
    }

    /**
     * Adds two 64-bit numbers with 5 addends. Works faster than adding them one by one.
     */
    private static int64add5(dst: any, a: any, b: any, c: any, d: any, e: any) {
        const w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff) + (e.l & 0xffff);
        const w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (e.l >>> 16) + (w0 >>> 16);
        const w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (e.h & 0xffff) + (w1 >>> 16);
        const w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (e.h >>> 16) + (w2 >>> 16);
        dst.l = (w0 & 0xffff) | (w1 << 16);
        dst.h = (w2 & 0xffff) | (w3 << 16);
    }

    private static _extend(source: any, size_ref: any) {
        let extended = "";
        for (let i = 0; i < Math.floor(size_ref / 64); i++)
            extended += source;
        extended += source.substr(0, size_ref % 64);
        return extended;
    }

    // steps 1-12
    private _sha512crypt_intermediate(password: any, salt: any) {
        // const digest_a = this.rstr_sha512(password + salt);
        const digest_b = this.rstr_sha512(password + salt + password);
        const key_len = password.length;

        // extend digest b so that it has the same size as password
        const digest_b_extended = Delegate._extend(digest_b, password.length);

        let intermediate_input = password + salt + digest_b_extended;
        for (let cnt = key_len; cnt > 0; cnt >>= 1) {
            if ((cnt & 1) != 0)
                intermediate_input += digest_b
            else
                intermediate_input += password;
        }

        return this.rstr_sha512(intermediate_input);
    }

    private _rstr_sha512crypt(password: any, salt: any, rounds: any) {
        // steps 1-12
        const digest_a = this._sha512crypt_intermediate(password, salt);

        // step 13-15
        let dp_input = "";
        for (let i = 0; i < password.length; i++)
            dp_input += password;
        const dp = this.rstr_sha512(dp_input);
        // step 16
        const p = Delegate._extend(dp, password.length);

        // step 17-19
        let ds_input = "";
        for (let i = 0; i < (16 + digest_a.charCodeAt(0)); i++)
            ds_input += salt;
        const ds = this.rstr_sha512(ds_input);
        // step 20
        const s = Delegate._extend(ds, salt.length);

        // step 21
        let digest = digest_a;
        let c_input = "";
        for (let i = 0; i < rounds; i++) {
            c_input = "";

            if (i & 1)
                c_input += p;
            else
                c_input += digest;

            if (i % 3)
                c_input += s;

            if (i % 7)
                c_input += p;

            if (i & 1)
                c_input += digest;
            else
                c_input += p;

            digest = this.rstr_sha512(c_input);
        }

        return digest;
    };

    public sha512crypt(password: any, salt: any) {
        let magic = "$6$";
        let rounds;

        // parse the magic "$" stuff
        const magic_array = salt.split("$");
        if (magic_array.length > 1) {
            if (magic_array[1] !== "6") {
                const s = "Got '" + salt + "' but only SHA512 ($6$) algorithm supported";
                throw new Error(s);
            }
            rounds = parseInt(magic_array[2].split("=")[1]);
            if (rounds) {
                if (rounds < 1000)
                    rounds = 1000;
                if (rounds > 999999999)
                    rounds = 999999999;
                salt = magic_array[3] || salt;
            } else {
                salt = magic_array[2] || salt;
            }
        }

        // salt is max 16 chars long
        salt = salt.substr(0, 16);

        const input = this._rstr_sha512crypt(password, salt, rounds || 5000);
        let output = "";
        const tab = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        const order = [42, 21, 0,
            1, 43, 22,
            23, 2, 44,
            45, 24, 3,
            4, 46, 25,
            26, 5, 47,
            48, 27, 6,
            7, 49, 28,
            29, 8, 50,
            51, 30, 9,
            10, 52, 31,
            32, 11, 53,
            54, 33, 12,
            13, 55, 34,
            35, 14, 56,
            57, 36, 15,
            16, 58, 37,
            38, 17, 59,
            60, 39, 18,
            19, 61, 40,
            41, 20, 62,
            63];
        for (let i = 0; i < input.length; i += 3) {
            // special case for the end of the input
            if (order[i + 1] === undefined) {
                let char_1;
                let char_2;
                char_1 = input.charCodeAt(order[i]) & parseInt("00111111", 2);
                char_2 = (
                    input.charCodeAt(order[i]) & parseInt("11000000", 2)) >>> 6;
                output += tab.charAt(char_1) + tab.charAt(char_2);
            } else {
                let char_1;
                let char_2;
                let char_3;
                let char_4;
                char_1 = input.charCodeAt(order[i]) & parseInt("00111111", 2);
                char_2 = (
                    ((input.charCodeAt(order[i]) & parseInt("11000000", 2)) >>> 6) |
                    (input.charCodeAt(order[i + 1]) & parseInt("00001111", 2)) << 2);
                char_3 = (
                    ((input.charCodeAt(order[i + 1]) & parseInt("11110000", 2)) >> 4) |
                    (input.charCodeAt(order[i + 2]) & parseInt("00000011", 2)) << 4);
                char_4 = (input.charCodeAt(order[i + 2]) & parseInt("11111100", 2)) >>> 2;
                output += (tab.charAt(char_1) + tab.charAt(char_2) +
                    tab.charAt(char_3) + tab.charAt(char_4));
            }
        }

        if (magic_array.length > 2) {
            magic = rounds ? "$6$rounds=" + rounds + "$" : "$6$";
        }

        return magic + salt + "$" + output;
    }
}

/**
 * SHA-512, supporting hex, base64, crypt and HMAC hashes
 * @preferred
 */
export module sha512 {
    /**
     * Wrapper class based on https://github.com/mvo5/sha512crypt-node implementation.
     * This is not intended to be accessible for end-user.
     * @internal
     */
    const delegate = new Delegate();

    /**
     * Compute SHA-512 hash compatible with crypt implementation (`mkpasswd --method=sha-512`)
     * @param input - Input string to be hashed
     * @param salt - Salt to be used with algorithm. Can contain magic prefix. Eg. param `$6$rounds=1000$saltvalue` Will use version 6 of sha-512 with rounds decreased from default 5000 to 1000 and salt = `saltvalue`
     */
    export const crypt = (input: string, salt: string): string => delegate.sha512crypt(input, salt);

    /**
     * Compute SHA-512 hash with hexadecimal output
     * @param input - Input string to be hashed
     */
    export const hex = (input: string): string => delegate.rstr2hex(delegate.rstr_sha512(delegate.str2rstr_utf8(input)));

    /**
     * Compute SHA-512 hash with base64 output
     * @param input - Input string to be hashed
     */
    export const base64 = (input: string): string => delegate.rstr2b64(delegate.rstr_sha512(delegate.str2rstr_utf8(input)));

    /**
     * Compute SHA-512 hash with custom alphabet
     * @param input - Input string to be hashed
     * @param alphabet - Custom alphabet to build result hash
     */
    export const any = (input: string, alphabet: string): string => delegate.rstr2any(delegate.rstr_sha512(delegate.str2rstr_utf8(input)), alphabet);

    /**
     * Compute SHA-512 hash as hexadecimal with HMAC digest
     * @param key - HMAC key
     * @param data - Input data to be hashed
     */
    export const hexHmac = (key: string, data: string): string => delegate.rstr2hex(delegate.rstr_hmac_sha512(delegate.str2rstr_utf8(key), delegate.str2rstr_utf8(data)));

    /**
     * Compute SHA-512 hash as base64 with HMAC digest
     * @param key - HMAC key
     * @param data - Input data to be hashed
     */
    export const base64Hmac = (key: string, data: string): string => delegate.rstr2b64(delegate.rstr_hmac_sha512(delegate.str2rstr_utf8(key), delegate.str2rstr_utf8(data)));

    /**
     * Compute SHA-512 hash with HMAC digest and custom alphabet
     * @param key - HMAC key
     * @param data - Input data to be hashed
     * @param alphabet
     */
    export const anyHmac = (key: string, data: string, alphabet: string): string => delegate.rstr2any(delegate.rstr_hmac_sha512(delegate.str2rstr_utf8(key), delegate.str2rstr_utf8(data)), alphabet);

    /**
     * Set padding character for base64 output. Set `=` to be strictly compliant with RFC-4648.
     * Default padding is empty string.
     * This is global per-module option.
     * @param b64pad - Base64 padding character
     */
    export function setBase64Padding(b64pad?: string): void {
        delegate.b64pad = b64pad || '';
    }

    /**
     * Set HexCase for hex based methods.
     * Default is false.
     * This is global per-module option.
     * @param uppercase - true for uppercase output, false for lowercase output.
     */
    export function setHexCase(uppercase?: boolean): void {
        delegate.hexcase = uppercase ? 1 : 0;
    }
}
