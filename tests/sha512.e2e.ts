import {sha512} from '../src';
import {expect} from 'chai';
import {exec} from 'child_process';

describe('crypt e2e - requires bash and mkpasswd installed', function () {
    it('crypt default rounds', function () {
        exec('printf "password" | mkpasswd --stdin --method=sha-512 --salt=saltsalt', (error, stdout) => {
            if (error) throw error;
            let result = sha512.crypt("password", "saltsalt");
            let mkpasswdResult = stdout.trim();
            expect(result).equal(mkpasswdResult);
        });
    });
    it('crypt bulk', function () {
        this.timeout(30000);
        for (let i = 0; i<=100; i++){
            let characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            let passwdLength = Math.floor(1 + Math.random()*63);
            let saltLength = Math.floor(8 + Math.random()*8);
            let passwd = ''
            let salt = ''
            for (let ii = 0; ii < passwdLength; ii++ ) {
                passwd += characters.charAt(Math.floor(Math.random() * characters.length));
            }
            for (let iii = 0; iii < saltLength; iii++ ) {
                salt += characters.charAt(Math.floor(Math.random() * characters.length));
            }
            let command = `printf "${passwd}" | mkpasswd --stdin --method=sha-512 --salt=${salt}`;
            exec(command, (error, stdout) => {
                if (error) throw error;
                let result = sha512.crypt(passwd, salt);
                let mkpasswdResult = stdout.trim();
                expect(result, command).equal(mkpasswdResult);
            });
        }
    });
    it('should extend with long password', function () {
        this.timeout(30000);
        const input = new Array(64).join('a');
        let result = sha512.crypt(input, "saltsalt")
        exec(`printf "${input}" | mkpasswd --stdin --method=sha-512 --salt=saltsalt`, (error, stdout) => {
            if (error) throw error;
            let mkpasswdResult = stdout.trim();
            expect(result).equal(mkpasswdResult);
        });
    });
    it('should support $6$ salt format', function () {
        let result = sha512.crypt("password", "$6$saltsalt")
        exec(`printf "password" | mkpasswd --stdin --method=sha-512 --salt=saltsalt`, (error, stdout) => {
            if (error) throw error;
            let mkpasswdResult = stdout.trim();
            expect(result).equal(mkpasswdResult);
        });
    });
    it('should allow custom rounds=1000', function () {
        let result = sha512.crypt("password", "$6$rounds=1000$saltsalt")
        exec(`printf "password" | mkpasswd --stdin --method=sha-512 --salt=saltsalt -R 1000`, (error, stdout) => {
            if (error) throw error;
            let mkpasswdResult = stdout.trim();
            expect(result).equal(mkpasswdResult);
        });
    });
});
