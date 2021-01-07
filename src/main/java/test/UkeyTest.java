package test;


import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.ByteByReference;
import com.sun.jna.ptr.PointerByReference;

public class UkeyTest {

    public interface TestLoadDLL extends Library {
        TestLoadDLL INSTANCE = (TestLoadDLL) Native.loadLibrary("./lib/ukey", TestLoadDLL.class);
        public int Ukey_init(String pin);
        public void sign(String hash, long inLen, Pointer r, Pointer s);
        public long verify(String hash, long inLen, String r, String s);
    }


    public static void main(String[] args) {

        TestLoadDLL.INSTANCE.Ukey_init("111111");
        PointerByReference r = new PointerByReference();
        PointerByReference s = new PointerByReference();
        System.out.println(r.getPointer().SIZE);
        System.out.println(s.getPointer().SIZE);
        TestLoadDLL.INSTANCE.sign("abcd", 3L, r.getPointer(), s.getPointer());
        //System.out.println(r.getPointer().SIZE);
        for(int i = 0; i < r.getPointer().SIZE; i++){
            System.out.printf("%x ", r.getPointer().getByte(i));
        }
        System.out.println();
        //System.out.println(s.getPointer().SIZE);
        for(int i = 0; i < s.getPointer().SIZE; i++){
            System.out.printf("%x ", s.getPointer().getByte(i));
        }
    }

}
