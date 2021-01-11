package test;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.ByteByReference;
import com.sun.jna.ptr.PointerByReference;

import java.math.BigInteger;

public class UkeyTest {

    public interface TestLoadDLL extends Library {
        TestLoadDLL INSTANCE = (TestLoadDLL) Native.loadLibrary("./lib/ukeylib_v0.4/ukey", TestLoadDLL.class);
        public int Ukey_init(byte[] pin);
        public void sign(byte[] hash, long inLen, byte[] r, byte[] s);
        public long verify(byte[] hash, long inLen, byte[] r, byte[] s);
    }


    public static void main(String[] args) {

        //System.out.println(new BigInteger("167772172", 10).toString(16));

        byte[] pin = {'1', '1', '1', '1', '1', '1', '\0'};
        System.out.println(TestLoadDLL.INSTANCE.Ukey_init(pin));
        byte[] r = new byte[64];
        byte[] s = new byte[64];
        TestLoadDLL.INSTANCE.sign("12345678123456781234567812345678".getBytes(), 32L, r, s);
        //System.out.println(r.length);

        //System.out.println(s.length);
    }

}
