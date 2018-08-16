package beldon.proxy.server;

import beldon.proxy.config.ProxyConfigurer;
import beldon.proxy.config.properties.ProxyProperties;
import beldon.proxy.handler.ProxyServerHandler;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpServerCodec;

/**
 * @author Beldon
 * @create 2018-07-12 18:23
 */
public class HttpProxyServer extends AbstractProxyServer {

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;

    public HttpProxyServer(ProxyConfigurer configurer) {
        super(configurer);
        bossGroup = new NioEventLoopGroup();
        workerGroup = new NioEventLoopGroup();
    }

    @Override
    public void start() throws Exception {
        ProxyProperties configProperties = getConfigProperties();
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<Channel>() {

                        @Override
                        protected void initChannel(Channel ch) throws Exception {
                            ch.pipeline().addLast("httpCodec", new HttpServerCodec());
                            ch.pipeline().addLast("serverHandle", new ProxyServerHandler( HttpProxyServer.this));
                        }
                    });
            ChannelFuture f = b
                    .bind(configProperties.getPort())
                    .sync();
            f.channel().closeFuture().sync();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }

    @Override
    public void stop() throws Exception {
    }

}
