<?php

declare(strict_types=1);

class ClientSpake
{
    private FFI $ffi;
    private FFI\CData $storedData;
    private FFI\CData $publicData;
    private FFI\CData $serverState;
    private FFI\CData $clientState;
    private FFI\CData $sharedKeyFromServer;
    private FFI\CData $sharedKeyFromClient;
    private string $password;

    public function __construct(FFI $ffi)
    {
        $this->ffi = $ffi;
        $this->storedData = FFI::new('unsigned char[164]');
        $this->publicData = FFI::new('unsigned char[36]');
        $this->serverState = $this->ffi->new('crypto_spake_server_state');
        $this->clientState = $this->ffi->new('crypto_spake_client_state');
        $this->sharedKeyFromServer = $this->ffi->new('crypto_spake_shared_keys');
        $this->sharedKeyFromClient = $this->ffi->new('crypto_spake_shared_keys');
    }

    public function getSharedKeyFromServer(): FFI\CData
    {
        return $this->sharedKeyFromServer;
    }

    public function getStoredData(): \FFI\CData
    {
        return $this->storedData;
    }

    public function getPublicData(): \FFI\CData
    {
        return $this->publicData;
    }

    public function setPublicData(\FFI\CData $publicData): void
    {
        $this->publicData = $publicData;
    }

    public function setPassword(string $password): void
    {
        $this->password = $password;
    }

    public function initSharedData(string $password, string $salt): void
    {
        $this->password = $password;

        if (0 !== $this->ffi->crypto_spake_server_store(
                $this->storedData,
                $salt,
                $this->password,
                strlen($this->password),
                SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
            )) {
            throw new RuntimeException('Impossible to create the shared Data');
        }

        if (0 !== $this->ffi->crypto_spake_step0(FFI::addr($this->serverState), $this->publicData, $this->storedData)) {
            throw new RuntimeException('Impossible to create the client Data');
        }
    }

    /**
     * Client wants to authenticate to the server.
     */
    public function initiatePake(): FFI\CData
    {
        $responseClient = FFI::new('unsigned char[32]');

        if (0 !== $this->ffi->crypto_spake_step1(
                FFI::addr($this->clientState),
                $responseClient,
                $this->publicData,
                $this->password,
                strlen($this->password)
            )) {
            throw new RuntimeException('Impossible to create the client Response');
        }

        return $responseClient;
    }

    /**
     * Client receive Server Response and sends back it's shared key
     */
    public function handlePakeServerResponse(FFI\CData $pakeResponse): FFI\CData
    {
        $responseClient2 = FFI::new('unsigned char[32]');

        if (0 !== $this->ffi->crypto_spake_step3(
                FFI::addr($this->clientState),
                $responseClient2,
                FFI::addr($this->sharedKeyFromServer),
                CLIENT_ID,
                mb_strlen(CLIENT_ID)- 1,
                SERVER_ID,
                mb_strlen(SERVER_ID) - 1,
                $pakeResponse
            )) {
            throw new RuntimeException('Impossible to create the shared key client side');
        }

        return $responseClient2;
    }
}
