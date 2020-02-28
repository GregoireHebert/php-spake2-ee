<?php

declare(strict_types=1);

class ServerSpake
{
    private FFI $ffi;
    private FFI\CData $storedData;
    private FFI\CData $serverState;
    private FFI\CData $clientState;
    private FFI\CData $sharedKeyFromServer;
    private FFI\CData $sharedKeyFromClient;

    public function getSharedKeyFromClient(): FFI\CData
    {
        return $this->sharedKeyFromClient;
    }

    public function __construct(FFI $ffi, FFI\CData $storedData)
    {
        $this->ffi = $ffi;
        $this->initSharedData($storedData);
    }

    private function initSharedData(FFI\CData $storedData): void
    {
        $this->storedData = $storedData;
        $this->serverState = $this->ffi->new('crypto_spake_server_state');
        $this->clientState = $this->ffi->new('crypto_spake_client_state');
        $this->sharedKeyFromServer = $this->ffi->new('crypto_spake_shared_keys');
        $this->sharedKeyFromClient = $this->ffi->new('crypto_spake_shared_keys');
    }

    /**
     * Server receive the request and sends it's response to the client
     */
    public function handlePakeRequest(FFI\CData $pakeRequest): FFI\CData
    {
        $responseServer = FFI::new('unsigned char[64]');

        if (0 !== $this->ffi->crypto_spake_step2(
                FFI::addr($this->serverState),
                $responseServer,
                CLIENT_ID,
                mb_strlen(CLIENT_ID) - 1,
                SERVER_ID,
                mb_strlen(SERVER_ID) - 1,
                $this->storedData,
                $pakeRequest
            )) {
            throw new RuntimeException('Impossible to create the server Response');
        }

        return $responseServer;
    }

    /**
     * Server receive the client shared key
     */
    public function handlePakeClientResponse(FFI\CData $pakeResponse): void
    {
        if (0 !== $this->ffi->crypto_spake_step4(
                FFI::addr($this->serverState),
                FFI::addr($this->sharedKeyFromClient),
                $pakeResponse
            )) {
            throw new RuntimeException('Impossible to create the shared key server side');
        }
    }
}

