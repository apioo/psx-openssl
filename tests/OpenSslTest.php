<?php
/*
 * PSX is a open source PHP framework to develop RESTful APIs.
 * For the current version and informations visit <http://phpsx.org>
 *
 * Copyright 2010-2016 Christoph Kappestein <k42b3.x@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace PSX\OpenSsl\Tests;

use PHPUnit\Framework\TestCase;
use PSX\OpenSsl\Exception;
use PSX\OpenSsl\OpenSsl;
use PSX\OpenSsl\PKey;

/**
 * OpenSslTest
 *
 * @author  Christoph Kappestein <k42b3.x@gmail.com>
 * @license http://www.apache.org/licenses/LICENSE-2.0
 * @link    http://phpsx.org
 */
class OpenSslTest extends TestCase
{
    protected function setUp(): void
    {
        if (!function_exists('openssl_pkey_new')) {
            $this->markTestSkipped('Openssl extension not installed');
        }
    }

    public function testEncryptDecrypt()
    {
        $data   = 'Secret text';
        $key    = 'foobar';
        $method = 'aes-128-cbc';
        $iv     = substr(md5('foo'), 4, 16);

        $encrypt = OpenSsl::encrypt($data, $method, $key, 0, $iv);

        $this->assertEquals('U1dIdXBaY25uOTRaZ3dhZ1l6QzQwZz09', base64_encode($encrypt));

        $decrypt = OpenSsl::decrypt($encrypt, $method, $key, 0, $iv);

        $this->assertEquals($data, $decrypt);
    }

    /**
     * This is essentially the openid association flow where two parties
     * establish a shared secret. Only the server/client public key and mac key
     * are transferred over the wire. The shared secret can then be used to
     * encrypt or sign data
     */
    public function testDhComputeKey()
    {
        // both parties must know these parameters
        $p      = pack('H*', 'dcf93a0b883972ec0e19989ac5a2ce310e1d37717e8d9571bb7623731866e61ef75a2e27898b057f9891c2e27a639c3f29b60814581cd3b2ca3986d2683705577d45c2e7e52dc81c7a171876e5cea74b1448bfdfaf18828efd2519f14e45e3826634af1949e5b535cc829a483b8a76223e5d490a257f05bdff16f2fb22c583ab');
        $g      = pack('H*', '02');
        $dhFunc = 'SHA256';

        // the client generates a new key
        $clientKey = new PKey(array(
            'private_key_type' => OPENSSL_KEYTYPE_DH,
            'dh' => array(
                'p' => $p,
                'g' => $g,
            )
        ));

        $details         = $clientKey->getDetails();
        $clientPublicKey = $details['dh']['pub_key'];

        // the server receives the public key of the client

        // the server generates a random secret
        $secret = OpenSsl::randomPseudoBytes(32);

        // the server creates a new key
        $serverKey = new PKey(array(
            'private_key_type' => OPENSSL_KEYTYPE_DH,
            'dh' => array(
                'p' => $p,
                'g' => $g,
            )
        ));

        $details         = $serverKey->getDetails();
        $serverPublicKey = $details['dh']['pub_key'];

        // the server generates the dh key
        $dhKey  = OpenSsl::dhComputeKey($clientPublicKey, $serverKey);
        $digest = OpenSsl::digest($dhKey, $dhFunc, true);
        $macKey = $digest ^ $secret;

        // the client receives the public key and mac key of the server
        $dhKey  = OpenSsl::dhComputeKey($serverPublicKey, $clientKey);
        $digest = OpenSsl::digest($dhKey, $dhFunc, true);
        $result = $digest ^ $macKey;

        // we have established a shared secret

        $this->assertEquals($secret, $result);
    }

    public function testDigest()
    {
        $methods = OpenSsl::getMdMethods();

        $this->assertTrue(is_array($methods));
        $this->assertTrue(count($methods) > 0);

        $data = OpenSsl::digest('foobar', 'SHA256');

        $this->assertEquals('c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2', $data);
    }

    public function testgetCipherMethods()
    {
        $methods = OpenSsl::getCipherMethods();

        $this->assertTrue(is_array($methods));
        $this->assertTrue(count($methods) > 0);
    }

    public function testOpenSeal()
    {
        $data = 'Some content';

        $key = $this->getKey();
        $key->export($privateKey, 'foobar');

        OpenSsl::seal($data, $sealed, $ekeys, array($key));

        $sealed = base64_encode($sealed);
        $envKey = base64_encode($ekeys[0]);

        OpenSsl::open(base64_decode($sealed), $opened, base64_decode($envKey), $key);

        $key->free();

        $this->assertEquals($data, $opened);
    }

    public function testSealInvalidPubKeyType()
    {
        $this->expectException(Exception::class);

        $data = 'Some content';

        OpenSsl::seal($data, $sealed, $ekeys, array('foo'));
    }

    public function testSignVerify()
    {
        $pkey = $this->getKey();

        $data = 'Some content';

        OpenSsl::sign($data, $signature, $pkey);

        $result = OpenSsl::verify($data, $signature, $pkey);

        $this->assertEquals('S9zEMrH5RTYkC/iUiHCbDUP9MkrsivkN23QffRuTD7bMiWn5neP4QX+36zO3ynELWUSyQ6woqNO37y6KQK1t6Nk3Etkau9IplBFga8ZDBcfMIMdJmWKXWmWzycgAorxjglFkdUSer8vc1tvf4v05msufJKwg/E853ZVZuB//vb/idxBH/GPeguGw8jm3DVEn3tpmypJMd/pzBwAzWB7USG8TsSDyXhxPt8pO3ZGCJn3IPbXo6eMMx+7ad/6yyxxHwu60Ab2F5hOIiC0UR15OLH5X7plJFWPTobi95GrVfHHHNRli1zquTt5T8cu+v3Q6W1ZOeSPqF7o7pn2nUjantQ==', base64_encode($signature));
        $this->assertEquals(1, $result);

        $data = 'Some content corrupted';

        $result = OpenSsl::verify($data, $signature, $pkey);

        $this->assertEquals(0, $result);

        $pkey->free();
    }

    public function testPublicEncryptPrivateDecrypt()
    {
        $pkey = $this->getKey();
        $pkey->export($privateKey, 'foobar');

        $data = 'Secret content';

        OpenSsl::publicEncrypt($data, $crypted, $pkey);

        $this->assertNotEmpty($crypted);

        OpenSsl::privateDecrypt($crypted, $decrypted, $pkey);

        $this->assertEquals($data, $decrypted);
    }

    public function testPrivateEncryptPublicDecrypt()
    {
        $pkey = $this->getKey();
        $pkey->export($privateKey, 'foobar');

        $data = 'Secret content';

        OpenSsl::privateEncrypt($data, $crypted, $pkey);

        $this->assertNotEmpty($crypted);

        OpenSsl::publicDecrypt($crypted, $decrypted, $pkey);

        $this->assertEquals($data, $decrypted);
    }

    public function testRandomPseudoBytes()
    {
        $data = OpenSsl::randomPseudoBytes(8);

        $this->assertEquals(8, strlen($data));
    }

    public function testErrorString()
    {
        $message = OpenSsl::errorString();

        $this->assertEquals('', $message);
    }

    protected function getKey()
    {
        $privateKey = <<<TEXT
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,AA056EDD41D3832C

fhMA8lDIGNiwdczPT8YZDCnDV6M8+mmpLCEOOVzLt68ecGJoNk0BADhN3BgXsmXe
pKkWdfVLco5FVwMJaFx21Kh9EmZWu9yRDJ1GMSn9HwPYdjm2v9lvPPoz2ELtqz9C
MjqLt7bU/YVKhy/bPVGoQPzO36Esj6qVhlQX7DhkCIf8ZrG8rYJFszn3B/9TaJ8/
CGf85F8tJ20/DOh+WQZI0wB53Plvpq/YX7JbTEgQV3YlCv4UZrCYl5TEBffv3CLL
Z+KBJ3u50LAWpouBY0Ljw+h0VeOODynq6dNzT/C60PwazZFqFzPijkTu021cTosc
7LwWL5hoOhcYDBI9SCS3PbRAqDWGwRR98SBzDg9I2MK59AgAuul+cSTKqCbgSZi1
VdL+uzmM6n5hnzn5gDF5pLNOjlp/Omwb6m49gmJ0LtdQCXqFPmafHW5QsAIPdVzT
veZuoE2NsQXnEpkqaq/lZlF8n+4I5ES8QlQByfEubRAtz2jaAJMB570CIVbtgt3r
PNLYJ0kV1uHAhNxuvfSIoIsFuHEgz+QXzDB4qync0JTomiNaVvRDjJzYwWe+CYmg
rnUEO3CnjigrCzVnI4HzJn9uWwzJ3y1ayHV914BM+gjaMRfFCA5Am0e5ci+7cnU+
CRTn3xyYESJdMy8ot7wiScI0NOSM8p4ph01OrZWWz8UxZNgDgorh9/2l9U0ugcfW
6BSmVPYWgtl4Yhh3umw2fP9/EIkULFNx/XSKzWkFbpvqAbnv80qZbl46Di94U8rj
P2CvWELxGmAIxoZ75XLIGoEoAN9mphs/Q1fUaawt7cRGuheH3usG7d/5a9EtL/GZ
Jvoqv3GdFtv0SHWxrHkArFTxqONwciu91NrGbUa2vFz2+bAS+egVRHVL5CdNzW5T
kVuneyHLqi/zvYrvpBN81ZV78ouWZzS7mYf/JwiUpkTpEFDSvGzy+ojYV5PPwmPV
esgz6lNUnPmCDDfwhgobYMIRT7mWXESBZKCqT2Nk4SvDaSSEfAhc44zKMFvGjznO
jnXuSM9PVh2G9ht0Ma+SaXmctKB5Zs4ym9cgFV1xWSYzUxpOuKc8ICdZAG8yuOL7
spUrwrYn1VHK+o11QOBHVnMsT4UUULTDfn2mTy5hrJDlDsSYOjZ8y72siB33b0zB
pmP6xYUm5NAtzmE0nPsCbyb+quTsTtbRIrdnGhCKXMRqZdEo+86M+eEGB8itRyE0
t5fscBw74mYagVOK2a8146B21LxcqCVkgheUaBBft1A629Ak9+Z8afpGXZ016tbV
zbDgV4LuEHuqW/HX/hyIHSBzh8sa96jpIvkFu3naxddDe0X4RZVO1CdDUyUUJg4P
5XgkAC+mmNLIcOvcbcfoZ5bnIyNv+ZaJgcU1Juh7LM/b9hYvuYSqYqsURFGzv2x9
lXSA/M7YcS8vXaNVfqINhZn9LFM9mQQ152cdMA1bmoUBeFvy8cMx86IPbOlql49S
tBc/hOSY90sjSkTIrX6V0GcHBp50z9j2pnSz66q4opo9/vPIXU4CDiC73OuQudZz
0CxBi7jJ0PeTN2CaDCYJJ7xG0ut7kGxXS0C9PFpzy+YLLRoNc0hdHnJMidyc1sgA
-----END RSA PRIVATE KEY-----
TEXT;

        return PKey::getPrivate($privateKey, 'foobar');
    }
}
