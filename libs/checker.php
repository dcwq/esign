<?php

class checker
{
    private $doc;

    private $cert;
    private $key;

    /**
     * Create checker object
     *
     * @param $fileName
     */

    public function __construct($fileName)
    {
        //load file
        $this->loadFile($fileName);

        //parse file
        $this->parseFile();

        //get certificate
        $this->cert = $this->getCertificate();
    }

    /**
     * Validate signature
     *
     * @return boolean
     */

    public function isValid()
    {
        $objXMLSecDSig = new XMLSecurityDSig();
        $objDSig = $objXMLSecDSig->locateSignature($this->doc);

        $objXMLSecDSig->canonicalizeSignedInfo();

        return $objXMLSecDSig->verify($this->key);
    }

    /**
     * Get certificate attributes info
     *
     * @return array
     */

    public function getCertInfo()
    {
        $certInfo = openssl_x509_parse($this->cert);

        $info = array();

        foreach ($certInfo['subject'] as $k => $v)
        {
            $info['subject'][$this->getAttributeLongName($k)] = $v;
        }

        foreach ($certInfo['issuer'] as $k => $v)
        {
            $info['issuer'][$this->getAttributeLongName($k)] = $v;
        }

        $info['Validity period']['From'] = date('Y-m-d', $certInfo['validFrom_time_t']);
        $info['Validity period']['To'] = date('Y-m-d', $certInfo['validTo_time_t']);

        return $info;
    }

    /**
     * Load file
     *
     * @param $fileName
     * @throws Exception
     */

    private function loadFile($fileName)
    {
        if (!file_exists($fileName))
            throw new Exception('File not found');

        $this->doc = new DOMDocument();
        $this->doc->load($fileName);
    }

    /**
     * Parse file, locate signature, locate key
     *
     * @throws Exception
     */

    private function parseFile()
    {
        $objXMLSecDSig = new XMLSecurityDSig();

        $objDSig = $objXMLSecDSig->locateSignature($this->doc);
        $this->signature = $objDSig;

        $this->key = $objXMLSecDSig->locateKey();

        if (!$this->key)
        {
            throw new Exception("Key not found");
        }
    }

    /**
     * Get certificate
     *
     * @return mixed
     */

    private function getCertificate()
    {
        $objKeyInfo = XMLSecEnc::staticLocateKeyInfo($this->key, $this->signature);

        return $objKeyInfo->getX509Certificate();
    }

    /**
     * Converse short certificate attribute nane to long version
     *
     * @param $shortname
     * @return string
     */

    private function getAttributeLongName($shortname)
    {
        switch ($shortname)
        {
            default: $long = $shortname; break;
            case 'countryName': case 'C': $long = 'Country'; break;
            case 'organizationName': case 'O': $long = 'Organization'; break;
            case 'organizationalUnitName': case 'OU': $long = 'Organizational unit'; break;
            case 'dnQualifier': $long = 'Distinguished name qualifier'; break;
            case 'stateOrProvinceName': case 'ST': $long = 'Country'; break;
            case 'commonName': case 'CN': $long = 'Common name'; break;
            case 'serialNumber': $long = 'Serial number'; break;
            case 'locality': case 'L': $long = 'Locality'; break;
            case 'title': $long = 'Title'; break;
            case 'surName': case 'SN': $long = 'Surname'; break;
            case 'givenName': case 'GN': $long = 'Given name'; break;
            case 'emailAddress': $long = 'Email'; break;
            case 'initials': $long = 'Initials'; break;
            case 'pseudonym': $long = 'Pseudonym'; break;
            case 'generationQualifier': $long = 'Generation qualifier'; break;
        }

        return $long;
    }

}