<?php

/* A client identifier (username, email address, public key...) */
define('CLIENT_ID', 'client');

/* A server identifier (IP address, host name, public key...) */
define('SERVER_ID', 'server');

$ffi = FFI::cdef(
    file_get_contents(__DIR__ . '/spake2-ee/src/crypto_spake.h'),
    __DIR__ . '/spake2-ee/src/crypto_spake.so'
);

require 'ClientSpake.php';
require 'ServerSpake.php';

$salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);

/****** THIS PART ASSUME WHAT SHOULD BE STORED SERVER SIDE *******/
$clientSpake = new ClientSpake($ffi);
// generate the values that need to be stored. (basically when the user registers, this is triggered, once.
// it could be done client side and server side.
$clientSpake->initSharedData('password', $salt);
// the stored data is what replaces the salt and the password.
// you store that in database for instance.
$storedData = $clientSpake->getStoredData();
$publicData = $clientSpake->getPublicData();

// now this is the server you want to authenticate, it has the storedData, so the hash from before.
$serverSpake = new ServerSpake($ffi, $storedData);
/****** END OF THIS PART *******/

// start a client, assuming that the user feed in the password.
$client2Spake = new ClientSpake($ffi);
$client2Spake->setPublicData($publicData); // <--- this bothers me a lot... I need to think about it.
$client2Spake->setPassword('password');
//$client2Spake->initSharedData('password');

// I want to authenticate, as client I initiate the password authentication key exchange by generating a shared value
// which I'll send over https to the server
$clientSharedValue = $client2Spake->initiatePake();

// The server receives the client shared value and will also generate a shared value which must be returned to the client.
$serverSharedValue = $serverSpake->handlePakeRequest($clientSharedValue);

// Client receive the server shared value, generate a shared key et return it to the client if the password do not match it fails
$clientSharedKey = $client2Spake->handlePakeServerResponse($serverSharedValue);

// Server receives the client shared key, generate it's own to be compared to the one received by the client
$serverSpake->handlePakeClientResponse($clientSharedKey);

//////

$clientCSK = [];
$serverCSK = [];
$clientSSK = [];
$serverSSK = [];

foreach ($client2Spake->getSharedKeyFromServer()->client_sk as $clientCSK[]);
foreach ($client2Spake->getSharedKeyFromServer()->server_sk as $clientSSK[]);
var_dump('CLIENT GET SERVER DATA', implode('', $clientCSK), implode('', $clientSSK));

foreach ($serverSpake->getSharedKeyFromClient()->client_sk as $serverCSK[]);
foreach ($serverSpake->getSharedKeyFromClient()->server_sk as $serverSSK[]);
var_dump('SERVER GET CLIENT DATA', implode('', $serverCSK), implode('', $serverSSK));

var_dump($clientCSK === $serverCSK);
var_dump($clientSSK === $serverSSK);
