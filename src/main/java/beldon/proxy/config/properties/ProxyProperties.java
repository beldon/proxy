package beldon.proxy.config.properties;

import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import lombok.Data;

/**
 * @author Beldon
 * @create 2018-07-12 18:17
 */
@Data
public class ProxyProperties {

    /**
     * 端口
     */
    private int port = 9999;

    private int maxContentLength = 65536;


    /**
     * 根证书目录
     */
    private String caPath;

    /**
     * 私钥路径
     */
    private String caPrivatePath;

    private EventLoopGroup loopGroup = new NioEventLoopGroup();

}
