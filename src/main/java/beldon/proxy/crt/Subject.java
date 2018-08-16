package beldon.proxy.crt;

import lombok.Builder;
import lombok.Data;

import java.lang.reflect.Field;
import java.util.*;

/**
 * @author Beldon
 * @create 2018-08-15 14:07
 */
@Builder
@Data
public class Subject implements Cloneable {

    /**
     * Country 国名
     */
    private String c;


    private String st;

    /**
     * State or province name,州/省名
     */
    private String s;

    /**
     * Locality 地理位置
     */
    private String l;

    /**
     * Organization name 机构名
     */
    private String o;

    /**
     * Organizational Unit name,	机构单元名称
     */
    private String ou;

    /**
     * Common Name, CN	通用名称
     */
    private String cn;


    @Override
    public String toString() {
        List<String> data = new ArrayList<>();
        Field[] fields = this.getClass().getDeclaredFields();
        try {
            for (Field field : fields) {
                String name = field.getName();
                field.setAccessible(true);
                Object o = field.get(this);
                if (o != null) {
                    data.add(name.toUpperCase() + "=" + o);
                }
            }
        } catch (IllegalAccessException e) {
            //ignore
        }
        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < data.size(); i++) {
            stringBuilder.append(data.get(i));
            if (i != data.size() - 1) {
                stringBuilder.append(", ");
            } else {
                stringBuilder.append(" ");
            }
        }
        return stringBuilder.toString().trim();
    }

    @Override
    public Subject clone() {
        return Subject.builder().cn(this.cn).ou(this.ou).o(this.o).l(this.l).s(this.s).st(this.st).c(this.c).build();
    }

    public String reverseToString() {
        StringBuilder stringBuilder = new StringBuilder();
        List<String> data = getDataList();

        for (int i = data.size() - 1; i >= 0; i--) {
            stringBuilder.append(data.get(i));
            if (i == 0) {
                stringBuilder.append(" ");
            } else {
                stringBuilder.append(", ");
            }
        }
        return stringBuilder.toString().trim();
    }

    private List<String> getDataList() {
        List<String> data = new ArrayList<>();
        Field[] fields = this.getClass().getDeclaredFields();
        try {
            for (Field field : fields) {
                String name = field.getName();
                field.setAccessible(true);
                Object o = field.get(this);
                if (o != null) {
                    data.add(name.toUpperCase() + "=" + o);
                }
            }
        } catch (IllegalAccessException e) {
            //ignore
        }
        return data;
    }

    /**
     * 解析 字符串 如 ：C=CN, ST=GuangDong, L=ShenZhen, O=Beldon, OU=Beldon, CN=Beldon
     *
     * @param subjectStr
     * @return
     */
    public static Subject parse(String subjectStr) {
        StringTokenizer st = new StringTokenizer(subjectStr, ", ");
        Map<String, String> values = new HashMap<>();
        while (st.hasMoreTokens()) {
            String token = st.nextToken();
            String[] split = token.split("=");
            if (split.length == 2) {
                values.put(split[0].toLowerCase(), split[1]);
            }
        }

        Subject subject = Subject.builder().build();
        Field[] fields = subject.getClass().getDeclaredFields();
        try {
            for (Field field : fields) {
                String name = field.getName();
                if (values.containsKey(name)) {
                    field.setAccessible(true);
                    field.set(subject, values.get(name));
                }
            }
        } catch (IllegalAccessException e) {
            //ignore
        }
        return subject;
    }
}


