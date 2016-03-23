{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.OpenSSL.BN.Foreign where

import           Foreign.C.Types
import           Foreign.Ptr

data BN_CTX
data BIGNUM

foreign import ccall unsafe "&BN_CTX_free"
    ssl_bn_ctx_free :: FunPtr (Ptr BN_CTX -> IO ())

foreign import ccall unsafe "BN_CTX_new"
    ssl_bn_ctx_new :: IO (Ptr BN_CTX)

foreign import ccall unsafe "BN_new"
    ssl_bn_new :: IO (Ptr BIGNUM)

foreign import ccall unsafe "&BN_free"
    ssl_bn_free :: FunPtr (Ptr BIGNUM -> IO ())

foreign import ccall unsafe "BN_num_bits"
    ssl_bn_num_bits :: Ptr BIGNUM -> IO CInt

foreign import ccall unsafe "BN_bn2bin"
    ssl_bn_2bin :: Ptr BIGNUM -> Ptr CUChar -> IO CInt

foreign import ccall unsafe "BN_bin2bn"
    ssl_bn_bin2 :: Ptr CUChar -> CInt -> Ptr BIGNUM -> IO (Ptr BIGNUM)

-- bn_num_bytes is a macro, 
ssl_bn_num_bytes :: Ptr BIGNUM -> IO CInt
ssl_bn_num_bytes ptr = do
    bits <- ssl_bn_num_bits ptr
    return $ ((bits + 7) `div` 8)
