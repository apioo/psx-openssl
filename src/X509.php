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

namespace PSX\OpenSsl;

use InvalidArgumentException;
use ErrorHandleTrait;

/**
 * X509
 *
 * @author  Kage <kage@hackthissite.org>
 * @license http://www.apache.org/licenses/LICENSE-2.0
 * @link    https://www.hackthissite.org
 */
class X509
{

    protected $res;

    public function __construct($certificate)
    {
        if (is_string($certificate)) {
            $res = openssl_x509_read($certificate);

            self::handleReturn($res);

            $this->res = $res;
        } elseif (is_resource($certificate)) {
            $this->res = $certificate;
        } else {
            throw new InvalidArgumentException('Must be a valid file path, x509 certificate block, or a resource');
        }
    }

    public function free()
    {
        openssl_x509_free($this->res);
    }

    public function getResource()
    {
        return $this->res;
    }

    public function parse($shortnames = true)
    {
        $details = openssl_x509_parse($this->res, $shortnames);

        self::handleReturn($details);

        return $details;
    }

    public function export(&$out, $notext = true)
    {
        $result = openssl_x509_export($this->res, $out, $notext);

        self::handleReturn($result);

        return $result;
    }

    public function fingerprint($hash_algorithm = 'sha1', $raw_output = false)
    {
        $result = openssl_x509_fingerprint($this->res, $hash_algorithm, $raw_output);

        self::handleReturn($result);

        return $result;
    }

    public function checkPurpose($purpose_const = X509_PURPOSE_ANY, $ca_array = array(), $untrusted_file = '')
    {
        $result = openssl_x509_checkpurpose($this->res, $purpose_const, $ca_array, $untrusted_file);

        self::handleReturn($result);

        return $result;
    }
}
