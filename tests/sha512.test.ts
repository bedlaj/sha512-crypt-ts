import {sha512} from '../src';
import {expect, assert} from 'chai';

describe('sha512crypt', function () {
    it('sha512crypt default rounds', function () {
        let result = sha512.sha512crypt("password", "saltsalt")
        expect(result).equal("$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/");
    });
    it('should extend with long password', function () {
        let result = sha512.sha512crypt(new Array(64*3).join('a'), "saltsalt")
        expect(result).equal("$6$saltsalt$1waR97hj.De.si2aUKm7TSJMAKH8gA5wUQZqfW5XVNs6WkyBI03XjoIhm/3igFPeKIKlcRkUhA6CxtheIBE0a.");
    });
    it('should support $6$ salt format', function () {
        let result = sha512.sha512crypt("password", "$6$saltsalt")
        expect(result).equal("$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/");
    });
    it('sha512crypt rounds=1000', function () {
        let result = sha512.sha512crypt("password", "$6$rounds=1000$saltsalt")
        expect(result).equal("$6$rounds=1000$saltsalt$Z/J9iYO1iE9xnr8JPQL57ZWsVRtVjrUv3CiWc/wKWseqXgSqn3HFYJ/Ng7YXa8XlLj.wpdAwHOJJzuGFqBBRa0");
    });

    it('should adjust rounds to 1000', function () {
        let result = sha512.sha512crypt("password", "$6$rounds=10$saltsalt")
        expect(result).equal("$6$rounds=1000$saltsalt$Z/J9iYO1iE9xnr8JPQL57ZWsVRtVjrUv3CiWc/wKWseqXgSqn3HFYJ/Ng7YXa8XlLj.wpdAwHOJJzuGFqBBRa0");
    });

    it('sha512crypt should validate magic', function () {
        assert.throws(() => sha512.sha512crypt("password", "$5$saltsalt"), Error)
        assert.doesNotThrow(() => sha512.sha512crypt("password", "$6$saltsalt"), Error)
    });
});

describe('hex_sha512', function () {
    it('hex_sha512', function () {
        let result = sha512.hex_sha512("password")
        expect(result).equal("b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86");
    });
});

describe('b64_sha512', function () {
    it('b64_sha512', function () {
        let result = sha512.b64_sha512("password")
        expect(result).equal("sQnzu7wkTrgkQZF+0G1hi5AI3Qmzvv0bXgc5THBqi7mAsdd4Xll27ASbRt9fEyavWi6m0QP9B8lThf+rDKy8hg");
    });
});

describe('any_sha512', function () {
    it('any_sha512', function () {
        let result = sha512.any_sha512("password", "abcdefghijklmnopqrstuvwxyz")
        expect(result).equal("odierxibaponliebwlflopioxfecwnonfqnobxetqicaqcmudubiektpfxxmqfabiaymwbdjacqiezejveizuzmlpfmlchztagdwycubvelja");
    });
});

describe('hex_hmac_sha512', function () {
    it('hex_hmac_sha512', function () {
        let result = sha512.hex_hmac_sha512("key", "data")
        expect(result).equal("3c5953a18f7303ec653ba170ae334fafa08e3846f2efe317b87efce82376253cb52a8c31ddcde5a3a2eee183c2b34cb91f85e64ddbc325f7692b199473579c58");
    });
});

describe('b64_hmac_sha512', function () {
    it('b64_hmac_sha512', function () {
        let result = sha512.b64_hmac_sha512("key", "data")
        expect(result).equal("PFlToY9zA+xlO6FwrjNPr6COOEby7+MXuH786CN2JTy1Kowx3c3lo6Lu4YPCs0y5H4XmTdvDJfdpKxmUc1ecWA");
    });
});

describe('any_hmac_sha512', function () {
    it('any_hmac_sha512', function () {
        let result = sha512.any_hmac_sha512("key", "data", "abcdefghijklmnopqrstuvwxyz")
        expect(result).equal("evflztsrzjtlofxueexjfmfjpoprssqmtjxbldzredjwybsxckbpbodkpeepuhmkxsffbscclmdoftowbwfkmygwzoctetpcotxkwnriljglk");
    });
});
