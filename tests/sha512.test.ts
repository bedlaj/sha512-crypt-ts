import {sha512} from '../src';
import {assert, expect} from 'chai';

beforeEach(function () {
    sha512.setBase64Padding();
    sha512.setHexCase();
})

describe('crypt', function () {
    it('crypt default rounds', function () {
        let result = sha512.crypt("password", "saltsalt")
        expect(result).equal("$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/");
    });
    it('should extend with long password', function () {
        this.enableTimeouts(false);
        let result = sha512.crypt(new Array(64).join('a'), "saltsalt")
        expect(result).equal("$6$saltsalt$H8TWMaGNaWIlbCN.ve/rdRsHfqIqWBb7.bA3AXhg.LxuC9tFTrOvR1WclafJTyj/sTvPMjtI7XRtWpuVYDqys.");
    });
    it('should support $6$ salt format', function () {
        let result = sha512.crypt("password", "$6$saltsalt")
        expect(result).equal("$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/");
    });
    it('should allow custom rounds=1000', function () {
        let result = sha512.crypt("password", "$6$rounds=1000$saltsalt")
        expect(result).equal("$6$rounds=1000$saltsalt$Z/J9iYO1iE9xnr8JPQL57ZWsVRtVjrUv3CiWc/wKWseqXgSqn3HFYJ/Ng7YXa8XlLj.wpdAwHOJJzuGFqBBRa0");
    });

    it('should adjust rounds to 1000', function () {
        let result = sha512.crypt("password", "$6$rounds=10$saltsalt")
        expect(result).equal("$6$rounds=1000$saltsalt$Z/J9iYO1iE9xnr8JPQL57ZWsVRtVjrUv3CiWc/wKWseqXgSqn3HFYJ/Ng7YXa8XlLj.wpdAwHOJJzuGFqBBRa0");
    });

    it('crypt should validate magic', function () {
        assert.throws(() => sha512.crypt("password", "$5$saltsalt"), Error)
        assert.doesNotThrow(() => sha512.crypt("password", "$6$saltsalt"), Error)
    });

    it('crypt should validate salt length', function () {
        assert.throws(() => sha512.crypt("password", "1234567"), Error)
        assert.doesNotThrow(() => sha512.crypt("password", "12345678"), Error)
        assert.throws(() => sha512.crypt("password", "12345678901234567"), Error)
        assert.doesNotThrow(() => sha512.crypt("password", "123456780123456"), Error)
    });
});

describe('hex', function () {
    it('hexcase default', function () {
        let result = sha512.hex("password")
        expect(result).equal("b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86");
    });
    it('hexcase true', function () {
        sha512.setHexCase(true);
        let result = sha512.hex("password")
        expect(result).equal("B109F3BBBC244EB82441917ED06D618B9008DD09B3BEFD1B5E07394C706A8BB980B1D7785E5976EC049B46DF5F1326AF5A2EA6D103FD07C95385FFAB0CACBC86");
    });
    it('hexcase false', function () {
        sha512.setHexCase(false);
        let result = sha512.hex("password")
        expect(result).equal("b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86");
    });
});

describe('base64', function () {
    it('base64 default', function () {
        let result = sha512.base64("password")
        expect(result).equal("sQnzu7wkTrgkQZF+0G1hi5AI3Qmzvv0bXgc5THBqi7mAsdd4Xll27ASbRt9fEyavWi6m0QP9B8lThf+rDKy8hg");
    });
    it('base64 padding =', function () {
        sha512.setBase64Padding('=');
        let result = sha512.base64("password")
        expect(result).equal("sQnzu7wkTrgkQZF+0G1hi5AI3Qmzvv0bXgc5THBqi7mAsdd4Xll27ASbRt9fEyavWi6m0QP9B8lThf+rDKy8hg==");
    });
});

describe('any', function () {
    it('should allow custom alphabet', function () {
        let result = sha512.any("password", "abcdefghijklmnopqrstuvwxyz")
        expect(result).equal("odierxibaponliebwlflopioxfecwnonfqnobxetqicaqcmudubiektpfxxmqfabiaymwbdjacqiezejveizuzmlpfmlchztagdwycubvelja");
    });
});

describe('hexHmac', function () {
    it('hexHmac hexcase default', function () {
        let result = sha512.hexHmac("key", "data")
        expect(result).equal("3c5953a18f7303ec653ba170ae334fafa08e3846f2efe317b87efce82376253cb52a8c31ddcde5a3a2eee183c2b34cb91f85e64ddbc325f7692b199473579c58");
    });
    it('hexHmac hexcase false', function () {
        sha512.setHexCase(false);
        let result = sha512.hexHmac("key", "data")
        expect(result).equal("3c5953a18f7303ec653ba170ae334fafa08e3846f2efe317b87efce82376253cb52a8c31ddcde5a3a2eee183c2b34cb91f85e64ddbc325f7692b199473579c58");
    });
    it('hexHmac hexcase true', function () {
        sha512.setHexCase(true);
        let result = sha512.hexHmac("key", "data")
        expect(result).equal("3C5953A18F7303EC653BA170AE334FAFA08E3846F2EFE317B87EFCE82376253CB52A8C31DDCDE5A3A2EEE183C2B34CB91F85E64DDBC325F7692B199473579C58");
    });
    it('hexHmac hexcase reset to default', function () {
        sha512.setHexCase();
        let result = sha512.hexHmac("key", "data")
        expect(result).equal("3c5953a18f7303ec653ba170ae334fafa08e3846f2efe317b87efce82376253cb52a8c31ddcde5a3a2eee183c2b34cb91f85e64ddbc325f7692b199473579c58");
    });
});

describe('base64Hmac', function () {
    it('base64Hmac', function () {
        let result = sha512.base64Hmac("key", "data")
        expect(result).equal("PFlToY9zA+xlO6FwrjNPr6COOEby7+MXuH786CN2JTy1Kowx3c3lo6Lu4YPCs0y5H4XmTdvDJfdpKxmUc1ecWA");
    });
    it('base64Hmac with long key', function () {
        let result = sha512.base64Hmac(new Array(64*3).join('a'), "data")
        expect(result).equal("o+UJTdpnFdKWO6EjljXNfLEXy+wB1hB9JrV/Sz6J3RhsgvjtESmjTH9MYUMhM3cHeMiqVafW6vIyKNNsl78vYQ");
    });
    it('base64Hmac with pad =', function () {
        sha512.setBase64Padding('=');
        let result = sha512.base64Hmac("key", "data")
        expect(result).equal("PFlToY9zA+xlO6FwrjNPr6COOEby7+MXuH786CN2JTy1Kowx3c3lo6Lu4YPCs0y5H4XmTdvDJfdpKxmUc1ecWA==");
    });
    it('base64Hmac with pad empty', function () {
        sha512.setBase64Padding('');
        let result = sha512.base64Hmac("key", "data")
        expect(result).equal("PFlToY9zA+xlO6FwrjNPr6COOEby7+MXuH786CN2JTy1Kowx3c3lo6Lu4YPCs0y5H4XmTdvDJfdpKxmUc1ecWA");
    });
    it('base64Hmac with pad reset to default', function () {
        sha512.setBase64Padding();
        let result = sha512.base64Hmac("key", "data")
        expect(result).equal("PFlToY9zA+xlO6FwrjNPr6COOEby7+MXuH786CN2JTy1Kowx3c3lo6Lu4YPCs0y5H4XmTdvDJfdpKxmUc1ecWA");
    });
});

describe('anyHmac', function () {
    it('anyHmac', function () {
        let result = sha512.anyHmac("key", "data", "abcdefghijklmnopqrstuvwxyz")
        expect(result).equal("evflztsrzjtlofxueexjfmfjpoprssqmtjxbldzredjwybsxckbpbodkpeepuhmkxsffbscclmdoftowbwfkmygwzoctetpcotxkwnriljglk");
    });
});
