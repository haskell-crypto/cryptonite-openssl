{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.OpenSSL.BN where

import           Crypto.OpenSSL.BN.Foreign
import           Crypto.OpenSSL.Misc
import           Foreign.Ptr
import           Foreign.ForeignPtr

import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B

withIntegerAsBN :: Integer -> (Ptr BIGNUM -> IO a) -> IO a
withIntegerAsBN i f = do
    bn <- withForeignPtr fptr $ \bsPtr ->
            ssl_bn_bin2 (castPtr (bsPtr `plusPtr` o)) (fromIntegral len) nullPtr
    foreignBn <- newForeignPtr ssl_bn_free bn
    withForeignPtr foreignBn f
  where (fptr, o, len) = B.toForeignPtr bs
        bs = B.reverse $ B.unfoldr fdivMod256 i
        fdivMod256 0 = Nothing
        fdivMod256 n = Just (fromIntegral a,b) where (b,a) = divMod256 n
        divMod256 :: Integer -> (Integer, Integer)
        divMod256 n = (n `shiftR` 8, n .&. 0xff)

bnToInt :: Ptr BIGNUM -> IO Integer
bnToInt bn = do
    bytes <- ssl_bn_num_bytes bn
    bs    <- B.create (fromIntegral bytes) $ \bufPtr ->
                check $ ssl_bn_2bin bn (castPtr bufPtr)
    return $ os2ip bs
  where os2ip = B.foldl' (\a b -> (256 * a) .|. (fromIntegral b)) 0

withBnCtxNew :: (Ptr BN_CTX -> IO a) -> IO a
withBnCtxNew f = do
    -- UGLY, can do something more clever than this ..
    fptr <- ssl_bn_ctx_new >>= newForeignPtr ssl_bn_ctx_free
    withForeignPtr fptr f

withBnNew :: (Ptr BIGNUM -> IO a) -> IO a
withBnNew f = do
    fptr <- ssl_bn_new >>= newForeignPtr ssl_bn_free
    withForeignPtr fptr f
