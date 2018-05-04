<?php
/**
 *
 * @author Mikael Peigney
 */

namespace Mika56\SPFCheck;


use Mika56\SPFCheck\Exception\DNSLookupException;
use Mika56\SPFCheck\Exception\DNSLookupLimitReachedException;

class DNSRecordGetter implements DNSRecordGetterInterface
{
    protected $requestCount = 0;
    protected $dnslookupcounter = true;

    /**
     * @param $domain string The domain to get SPF record
     * @return string[] The SPF record(s)
     * @throws DNSLookupException
     */
    public function getSPFRecordForDomain($domain)
    {
        $records = dns_get_record($domain, DNS_TXT | DNS_SOA);
        if (false === $records) {
            throw new DNSLookupException;
        }

        $spfRecords = array();
        foreach ($records as $record) {
            if ($record['type'] == 'TXT') {
                $txt = strtolower($record['txt']);
                // An SPF record can be empty (no mechanism)
                if ($txt == 'v=spf1' || stripos($txt, 'v=spf1 ') === 0) {
                    $spfRecords[] = $txt;
                }
            }
        }

        return $spfRecords;
    }

    /**
     * @param $domain string The domain to get DKIM record
     * @parem $selector string The DKIM selector
     * @return string[] The DKIM record(s)
     * @throws DNSLookupException
     */
    public function getDKIMRecordForDomain($domain, $selector)
    {
        $records = dns_get_record($selector . '._domainkey.' . $domain, "TXT");
        if (false === $records) {
            throw new DNSLookupException;
        }

        $dkimRecords = array();
        foreach ($records as $record) {
            if ($record['type'] == 'TXT') {
                $txt = strtolower($record['txt']);
                // An SPF record can be empty (no mechanism)
                if ($txt == 'v=DKIM1' || stripos($txt, 'v=DKIM1 ') === 0) {
                    $dkimRecords[] = $txt;
                }
            }
        }

        return $dkimRecords;
    }

    public function resolveA($domain, $ip4only = false)
    {
        $records = dns_get_record($domain, $ip4only ? DNS_A : (DNS_A | DNS_AAAA));
        if (false === $records) {
            throw new DNSLookupException;
        }

        $addresses = [];

        foreach ($records as $record) {
            if ($record['type'] === "A") {
                $addresses[] = $record['ip'];
            } elseif ($record['type'] === 'AAAA') {
                $addresses[] = $record['ipv6'];
            }
        }

        return $addresses;
    }

    public function resolveMx($domain)
    {
        $records = dns_get_record($domain, DNS_MX);
        if (false === $records) {
            throw new DNSLookupException;
        }

        $addresses = [];

        foreach ($records as $record) {
            if ($record['type'] === "MX") {
                $addresses[] = $record['target'];
            }
        }

        return $addresses;
    }

    public function resolvePtr($ipAddress)
    {
        if (stripos($ipAddress, '.') !== false) {
            // IPv4
            $revIp = implode('.', array_reverse(explode('.', $ipAddress))).'.in-addr.arpa';
        } else {
            $literal = implode(':', array_map(function ($b) {
                return sprintf('%04x', $b);
            }, unpack('n*', inet_pton($ipAddress))));
            $revIp   = strtolower(implode('.', array_reverse(str_split(str_replace(':', '', $literal))))).'.ip6.arpa';
        }

        $revs = array_map(function ($e) {
            return $e['target'];
        }, dns_get_record($revIp, DNS_PTR));

        return array_slice($revs, 0, 10);
    }

    public function exists($domain)
    {
        try {
            return count($this->resolveA($domain, true)) > 0;
        } catch (DNSLookupException $e) {
            return false;
        }
    }

    public function resetRequestCount()
    {
        $this->requestCount = 0;
    }

    public function countRequest()
    {
        if (++$this->requestCount > 10) {
            if ($this->dnslookupcounter)
            {
                throw new DNSLookupLimitReachedException();
            }
        }
    }

    public function getCountRequest()
    {
        return $this->requestCount;
    }

    public function setDNSLookupCounter($active)
    {
        $this->dnslookupcounter = $active;
    }
}