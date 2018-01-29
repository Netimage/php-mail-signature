<?php

namespace Pms;

/**
 * php-mail-signature
 *
 * https://github.com/louisameline/php-mail-signature
 * Author:	Louis Ameline - 04/2012
 *
 *
 * This stand-alone DKIM class is based on the work made on PHP-MAILER (see license below).
 * The differences are :
 * - it is a standalone class
 * - it supports Domain Keys header
 * - it supports UTF-8
 * - it will let you choose the headers you want to base the signature on
 * - it will let you choose between simple and relaxed body canonicalization
 *
 * If the class fails to sign the e-mail, the returned DKIM header will be empty and the mail
 * will still be sent, just unsigned. A php warning is thrown for logging.
 *
 * NOTE: you will NOT be able to use Domain Keys with PHP's mail() function, since it does
 * not allow to prepend the DK header before the To and Subject ones. DKIM is ok with that,
 * but Domain Keys is not. If you still want Domain Keys, you will have to manage to send
 * your mail straight to your MTA without the mail() function.
 *
 * Successfully tested against Gmail, Yahoo Mail, Live.com, appmaildev.com
 * Hope it helps and saves you plenty of time. Let me know if you find issues.
 *
 * For more info, you should read :
 * @link http://www.ietf.org/rfc/rfc4871.txt
 * @link http://www.zytrax.com/books/dns/ch9/dkim.html
 *
 * @link https://github.com/louisameline/php-mail-signature
 * @author Louis Ameline
 * @version 1.0.3
 */

/*
 * Original PHPMailer CC info :
 * .---------------------------------------------------------------------------.
 * |  Software: PHPMailer - PHP email class                                    |
 * |   Version: 5.2.1                                                          |
 * |      Site: https://code.google.com/a/apache-extras.org/p/phpmailer/       |
 * | ------------------------------------------------------------------------- |
 * |     Admin: Jim Jagielski (project admininistrator)                        |
 * |   Authors: Andy Prevost (codeworxtech) codeworxtech@users.sourceforge.net |
 * |          : Marcus Bointon (coolbru) coolbru@users.sourceforge.net         |
 * |          : Jim Jagielski (jimjag) jimjag@gmail.com                        |
 * |   Founder: Brent R. Matzelle (original founder)                           |
 * | Copyright (c) 2010-2012, Jim Jagielski. All Rights Reserved.              |
 * | Copyright (c) 2004-2009, Andy Prevost. All Rights Reserved.               |
 * | Copyright (c) 2001-2003, Brent R. Matzelle                                |
 * | ------------------------------------------------------------------------- |
 * |   License: Distributed under the Lesser General Public License (LGPL)     |
 * |            http://www.gnu.org/copyleft/lesser.html                        |
 * | This program is distributed in the hope that it will be useful - WITHOUT  |
 * | ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or     |
 * | FITNESS FOR A PARTICULAR PURPOSE.                                         |
 * '---------------------------------------------------------------------------'
 * php-mail-signature class
 */
class MailSignature {

	/** @var string */
	private $privateKey;

	/** @var string */
	private $domain;

	/** @var string */
	private $selector;

	/** @var array */
	private $options;

	/** @var array */
	private $canonicalizedHeadersRelaxed;

	/**
	 * MailSignature constructor.
	 * @param string $privateKey Either file path to .pem signature file or PEM formatted string
	 * @param string $passPhrase PassPhrase to PEM private key
	 * @param string $domain Domain or subdomain of the signing entity (i.e. the domain where the e-mail comes from)
	 * @param string $selector Selector used in your DKIM DNS record, e.g. : $selector._domainkey.$domain
	 * @param array $options
	 */
	public function __construct($privateKey, $passPhrase, $domain, $selector, $options = []) {
		
		// prepare the resource
		$this->privateKey = openssl_get_privatekey($privateKey, $passPhrase);
		$this->domain = $domain;
		$this->selector = $selector;
		
		/*
		 * This function will not let you ask for the simple header canonicalization because
		 * it would require more code, it would not be more secure and mails would yet be
		 * more likely to be rejected : no point in that
		 */
		$defaultOptions = array(
			'use_dkim' => true,
			// disabled by default, see why at the top of this file
			'use_domainKeys' => false,
			/*
			 * Allowed user, defaults is "@<MAIL_DKIM_DOMAIN>", meaning anybody in the
			 * MAIL_DKIM_DOMAIN domain. Ex: 'admin@mydomain.tld'. You'll never have to use
			 * this unless you do not control the "From" value in the e-mails you send.
			 */
			'identity' => null,
			// "relaxed" is recommended over "simple" for better chances of success
			'dkim_body_canonicalization' => 'relaxed',
			// "nofws" is recommended over "simple" for better chances of success
			'dk_canonicalization' => 'nofws',
			/*
			 * The default list of headers types you want to base the signature on. The
			 * types here (in the default options) are to be put in lower case, but the
			 * types in $options can have capital letters. If one or more of the headers
			 * specified are not found in the $headers given to the function, they will
			 * just not be used.
			 * If you supply a new list, it will replace the default one
			 */
			'signed_headers' => array(
				'mime-version',
				'from',
				'to',
				'subject',
				'reply-to'
			)
		);
		
		if(isset($options['signed_headers'])){
			// lower case fields
			$options['signed_headers'] = array_map('strtolower', $options['signed_headers']);

			// delete the default fields if a custom list is provided, not merge
			$defaultOptions['signed_headers'] = [];
		}
		
		$this->options = array_replace_recursive($defaultOptions, $options);
	}

	/**
	 * This function returns an array of relaxed canonicalized headers (lowercases the
	 * header type and cleans the new lines/spaces according to the RFC requirements).
	 * only headers required for signature (specified by $options) will be returned
	 * the result is an array of the type : array(headerType => fullHeader [, ...]),
	 * e.g. array('mime-version' => 'mime-version:1.0')
	 * @param $sHeaders
	 * @return array
	 */
	private function dkimCanonicalizeHeadersRelaxed($sHeaders) {
		$aHeaders = [];
		
		// a header value which is spread over several lines must be 1-lined
		$sHeaders = preg_replace("/\n\s+/", " ", $sHeaders);
		
		$lines = explode("\r\n", $sHeaders);
		
		foreach ($lines as $key => $line) {
			// delete multiple WSP
			$line = preg_replace("/\s+/", ' ', $line);
			
			if (!empty($line)) {
				// header type to lowercase and delete WSP which are not part of the header value
				$line = explode(':', $line, 2);
				
				$header_type = trim(strtolower($line[0]));
				$header_value = trim($line[1]);
				
				if (in_array(strtolower($header_type), $this->options['signed_headers']) || strtolower($header_type) == 'dkim-signature') {
					$aHeaders[$header_type] = $header_type . ':' . $header_value;
				}
			}
		}
		
		return $aHeaders;
	}

	/**
	 * Apply RFC 4871 requirements before body signature. Do not modify
	 * @param string $body
	 * @return string
	 */
	private function dkimCanonicalizeBodySimple($body) {
		/*
		 * Unlike other libraries, we do not convert all \n in the body to \r\n here
		 * because the RFC does not specify to do it here. However it should be done
		 * anyway since MTA may modify them and we recommend you do this on the mail
		 * body before calling this DKIM class - or signature could fail.
		 */
		
		// remove multiple trailing CRLF
		while (mb_substr($body, mb_strlen($body, 'UTF-8')-4, 4, 'UTF-8') == "\r\n\r\n") {
			$body = mb_substr($body, 0, mb_strlen($body, 'UTF-8')-2, 'UTF-8');
		}
		
		// must end with CRLF anyway
		if (mb_substr($body, mb_strlen($body, 'UTF-8')-2, 2, 'UTF-8') != "\r\n") {
			$body .= "\r\n";
		}
		
		return $body;
	}

	/**
	 * Apply RFC 4871 requirements before body signature. Do not modify
	 * @param string $body
	 * @return string
	 */
	private function dkimCanonicalizeBodyRelaxed($body) {
		$lines = explode("\r\n", $body);
		
		foreach ($lines as $key => $value) {
			// ignore WSP at the end of lines
			$value = rtrim($value);
			
			// ignore multiple WSP inside the line
			$lines[$key] = preg_replace('/\s+/', ' ', $value);
		}
		
		$body = implode("\r\n", $lines);
		
		// ignore empty lines at the end
		$body = $this->dkimCanonicalizeBodySimple($body);
		
		return $body;
	}

	/**
	 * Apply RFC 4870 requirements before body signature. Do not modify
	 * @param string $body
	 * @param string $sHeaders
	 * @return string
	 */
	private function dkCanonicalizeSimple($body, $sHeaders) {
		/*
		 * Note : the RFC assumes all lines end with CRLF, and we assume you already
		 * took care of that before calling the class
		 */
		
		// keep only headers wich are in the signature headers
		$aHeaders = explode("\r\n", $sHeaders);
		foreach ($aHeaders as $key => $line) {
			if (!empty($aHeaders)) {
				// make sure this line is the line of a new header and not the
				// continuation of another one
				$c = substr($line, 0, 1);
				$is_signed_header = true;
				
				// new header
				if (!in_array($c, array("\r", "\n", "\t", ' '))) {
					$h = explode(':', $line);
					$header_type = strtolower(trim($h[0]));
					
					// keep only signature headers
					if (in_array($header_type, $this->options['signed_headers'])) {
						$is_signed_header = true;
					} else {
						unset($aHeaders[$key]);
						$is_signed_header = false;
					}
				} else {
				// continuated header
					// do not keep if it belongs to an unwanted header
					if ($is_signed_header == false) {
						unset($aHeaders[$key]);
					}
				}
			}
			else {
				unset($aHeaders[$key]);
			}
		}
		$sHeaders = implode("\r\n", $aHeaders);
		
		$mail = $sHeaders."\r\n\r\n".$body."\r\n";
		
		// remove all trailing CRLF
		while(mb_substr($body, mb_strlen($mail, 'UTF-8')-4, 4, 'UTF-8') == "\r\n\r\n"){
			$mail = mb_substr($mail, 0, mb_strlen($mail, 'UTF-8')-2, 'UTF-8');
		}
		
		return $mail;
	}

	/**
	 * Apply RFC 4870 requirements before body signature. Do not modify
	 * @param string $body
	 * @param string $sHeaders
	 * @return string
	 */
	private function dkCanonicalizeNofws($body, $sHeaders) {
		// HEADERS
		// a header value which is spread over several lines must be 1-lined
		$sHeaders = preg_replace("/\r\n\s+/", " ", $sHeaders);
		
		$aHeaders = explode("\r\n", $sHeaders);
		
		foreach ($aHeaders as $key => $line) {
			if (!empty($line)) {
				$h = explode(':', $line);
				$header_type = strtolower(trim($h[0]));
				
				// keep only signature headers
				if (in_array($header_type, $this->options['signed_headers'])) {
					// delete all WSP in each line
					$aHeaders[$key] = preg_replace("/\s/", '', $line);
				} else {
					unset($aHeaders[$key]);
				}
			} else {
				unset($aHeaders[$key]);
			}
		}
		$sHeaders = implode("\r\n", $aHeaders);
		
		// BODY
		// delete all WSP in each body line
		$body_lines = explode("\r\n", $body);
		
		foreach ($body_lines as $key => $line) {
			$body_lines[$key] = preg_replace("/\s/", '', $line);
		}
		
		$body = rtrim(implode("\r\n", $body_lines))."\r\n";
		
		return $sHeaders."\r\n\r\n".$body;
	}
	
	/**
	 * The function will return no DKIM header (no signature) if there is a failure,
	 * so the mail will still be sent in the default unsigned way
	 * it is highly recommended that all linefeeds in the $body and $headers you submit
	 * are in the CRLF (\r\n) format !! Otherwise signature may fail with some MTAs
	 */
	private function getDkimHeader($body) {
		
		$body =
			($this->options['dkim_body_canonicalization'] == 'simple') ?
			$this->dkimCanonicalizeBodySimple($body) :
			$this->dkimCanonicalizeBodyRelaxed($body);
		
		// Base64 of packed binary SHA-256 hash of body
		$bh = rtrim(base64_encode(pack("H*", hash('sha256', $body))), "\r\n\t");
		$i_part =
			($this->options['identity'] == null) ?
			'' :
			' i='.$this->options['identity'].';'."\r\n\t";
		
		$dkim_header =
			'DKIM-Signature: '.
				'v=1;'."\r\n\t".
				'a=rsa-sha256;'."\r\n\t".
				'q=dns/txt;'."\r\n\t".
				's='.$this->selector.';'."\r\n\t".
				't='.time().';'."\r\n\t".
				'c=relaxed/'.$this->options['dkim_body_canonicalization'].';'."\r\n\t".
				'h='.implode(':', array_keys($this->canonicalizedHeadersRelaxed)).';'."\r\n\t".
				'd='.$this->domain.';'."\r\n\t".
				$i_part.
				'bh='.$bh.';'."\r\n\t".
				'b=';
		
		// now for the signature we need the canonicalized version of the $dkim_header
		// we've just made
		$canonicalized_dkim_header = $this->dkimCanonicalizeHeadersRelaxed($dkim_header);
		
		// we sign the canonicalized signature headers
		$to_be_signed = implode("\r\n", $this->canonicalizedHeadersRelaxed) . "\r\n" . $canonicalized_dkim_header['dkim-signature'];
		
		// $signature is sent by reference in this function
		$signature = '';
		if(openssl_sign($to_be_signed, $signature, $this->privateKey, OPENSSL_ALGO_SHA256)){
			$hash = rtrim(base64_encode($signature), "\r\n\t")."\r\n";
			$dkim_header .= $hash;
		}
		else {
			trigger_error(sprintf('Could not sign e-mail with DKIM : %s', $to_be_signed), E_USER_WARNING);
			$dkim_header = '';
		}
		
		return $dkim_header;
	}
	
	private function getDkHeader($body, $sHeaders) {
		// Creating DomainKey-Signature
		$domainkeys_header =
			'DomainKey-Signature: '.
				'a=rsa-sha1; '."\r\n\t".
				'c='.$this->options['dk_canonicalization'].'; '."\r\n\t".
				'd='.$this->domain.'; '."\r\n\t".
				's='.$this->selector.'; '."\r\n\t".
				'h='.implode(':', array_keys($this->canonicalizedHeadersRelaxed)).'; '."\r\n\t".
				'b=';
		
		// we signed the canonicalized signature headers + the canonicalized body
		$to_be_signed =
			($this-> options['dk_canonicalization'] == 'simple') ?
			$this->dkCanonicalizeSimple($body, $sHeaders) :
			$this->dkCanonicalizeNofws($body, $sHeaders);
		
		$signature = '';
		if (openssl_sign($to_be_signed, $signature, $this->privateKey, OPENSSL_ALGO_SHA1)) {
			$domainkeys_header .= rtrim(chunk_split(base64_encode($signature), 64, "\r\n\t"))."\r\n";
		} else {
			$domainkeys_header = '';
		}
		
		return $domainkeys_header;
	}

	/**
	 * You may leave $to and $subject empty if the corresponding headers are already
	 * in $headers
	 * @deprecated Use getSignedHeaders instead
	 */
	public function get_signed_headers($to, $subject, $body, $headers){
		return $this->getSignedHeaders($to, $subject, $body, $headers);
	}

	/**
	 * You may leave $to and $subject empty if the corresponding headers are already
	 * in $headers
	 * @param string $to
	 * @param string $subject
	 * @param string $body
	 * @param string $headers
	 * @return string
	 */
	public function getSignedHeaders($to, $subject, $body, $headers) {
		$signedHeaders = '';
		
		if(!empty($to) or !empty($subject)){
			
			/*
			 * To and Subject are not supposed to be present in $headers if you
			 * use the php mail() function, because it takes care of that itself in
			 * parameters for security reasons, so we reconstruct them here for the
			 * signature only
			 */
			$headers .=
				(mb_substr($headers, mb_strlen($headers, 'UTF-8')-2, 2, 'UTF-8') == "\r\n") ?
				'' :
				"\r\n";
			
			if(!empty($to)) $headers .= 'To: '.$to."\r\n";
			if(!empty($subject)) $headers .= 'Subject: '.$subject."\r\n";
		}
		
		// get the clean version of headers used for signature
		$this->canonicalizedHeadersRelaxed = $this->dkimCanonicalizeHeadersRelaxed($headers);
		
		if(!empty($this->canonicalizedHeadersRelaxed)){
			
			// Domain Keys must be the first header, it is an RFC (stupid) requirement
			if($this->options['use_domainKeys'] == true){
				$signedHeaders .= $this->getDkHeader($body, $headers);
			}
			
			if($this->options['use_dkim'] == true){
				$signedHeaders .= $this->getDkimHeader($body);
			}
		}
		else {
			trigger_error('No headers found to sign the e-mail with !', E_USER_WARNING);
		}
		
		return $signedHeaders;
	}
}
