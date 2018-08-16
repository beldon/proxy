package beldon.proxy.handler;

import beldon.proxy.crt.CertFactory;
import beldon.proxy.crt.CertHolder;
import beldon.proxy.filter.ProxyFilter;
import beldon.proxy.filter.chain.*;
import beldon.proxy.server.RequestProtocol;
import beldon.proxy.server.ServerResource;
import beldon.proxy.util.ProtocolUtil;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.ReferenceCountUtil;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

@Slf4j
public class ProxyServerHandler extends ChannelInboundHandlerAdapter {
    private ChannelFuture cf;
    private String host;
    private int port;
    private RequestProtocol requestProto;
    private ServerResource serverResource;
    private CertFactory certFactory;
    private List requestList = new ArrayList<>();
    private boolean isConnect;
    private int status = 0;
    private final ProxyFilterChain filterChain;


    public ProxyServerHandler(ServerResource serverResource) {
        this.serverResource = serverResource;
        this.certFactory = serverResource.getCertFactory();
        this.filterChain = serverResource.getFilterChin(application());
    }

    @Override
    public void channelRead(final ChannelHandlerContext ctx, final Object msg) throws Exception {
        if (msg instanceof HttpRequest) {
            HttpRequest request = (HttpRequest) msg;
            if (status == 0) {

                if (requestProto == null) {
                    requestProto = ProtocolUtil.getRequestProtocol(request);
                    this.host = requestProto.getHost();
                    this.port = requestProto.getPort();
                }
                if (requestProto == null) {
                    //bad request
                    ctx.channel().close();
                    return;
                }
                status = 1;
                if (isConnect(request.method())) {
                    status = 2;
                    //建立代理握手
                    //第一次建立连接取host和端口号和处理代理握手
                    HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
                    ctx.writeAndFlush(response);
                    ctx.channel().pipeline().remove("httpCodec");
                    return;
                }
            }
            filterChain.doFilter(ctx.channel(), request);
        } else if (msg instanceof HttpContent) {
            if (status != 2) {
                HttpContent httpContent = (HttpContent) msg;
                filterChain.doFilter(ctx.channel(), httpContent);
            } else {
                ReferenceCountUtil.release(msg);
                status = 1;
            }
        } else {
            ByteBuf byteBuf = (ByteBuf) msg;
            if (byteBuf.getByte(0) == 22) {
                //ssl握手
                requestProto.setSsl(true);
                CertHolder certHolder = serverResource.getCertHolder();
                SslContext sslCtx = SslContextBuilder
                        .forServer(certHolder.getServerPriKey(), certFactory.getCert(this.host))
                        .build();
                ctx.pipeline().addFirst("httpCodec", new HttpServerCodec());
                ctx.pipeline().addFirst("sslHandle", sslCtx.newHandler(ctx.alloc()));
                //重新过一遍pipeline，拿到解密后的的http报文
                ctx.pipeline().fireChannelRead(msg);
                //处理后的ssl能看到解密后的报文
                return;
            }
            handleProxyData(ctx.channel(), msg);
        }
    }

    @Override
    public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
        if (cf != null) {
            cf.channel().close();
        }
        ctx.channel().close();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        if (cf != null) {
            cf.channel().close();
        }
        ctx.channel().close();
    }

    private void handleProxyData(Channel channel, Object msg) {
        if (cf == null) {

            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(serverResource.getConfigProperties().getLoopGroup()) // 注册线程池
                    .channel(NioSocketChannel.class) // 使用NioSocketChannel来作为连接用的channel类
                    .handler(new ChannelInitializer() {
                        @Override
                        protected void initChannel(Channel ch) throws Exception {
                            if (requestProto.isSsl()) {
                                SslHandler sslHandler = serverResource.getClientSslContext()
                                        .newHandler(ch.alloc(), requestProto.getHost(), requestProto.getPort());
                                ch.pipeline().addLast(sslHandler);
                            }
                            ch.pipeline().addLast("httpCodec", new HttpClientCodec());
                            ch.pipeline().addLast("proxyClientHandle", new ProxyClientHandler(channel, filterChain));
                        }
                    });

            requestList = new LinkedList();
            cf = bootstrap.connect(host, port);
            cf.addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    future.channel().writeAndFlush(msg);
                    synchronized (requestList) {
                        requestList.forEach((obj) -> future.channel().writeAndFlush(obj));
                        requestList.clear();
                        isConnect = true;
                    }
                } else {
                    requestList.forEach((obj) -> ReferenceCountUtil.release(obj));
                    requestList.clear();
                    future.channel().close();
                    channel.close();
                }
            });
        } else {
            synchronized (requestList) {
                if (isConnect && cf.channel().isOpen()) {
                    cf.channel().writeAndFlush(msg);
                } else {
                    requestList.add(msg);
                }
            }
        }
    }

    private ProxyFilter application() {
        return new ProxyFilter() {
            @Override
            public void beforeRequest(Channel clientChannel, HttpRequest httpRequest, ProxyFilterRequestChain chain) {
                handleProxyData(clientChannel, httpRequest);
            }

            @Override
            public void beforeRequest(Channel clientChannel, HttpContent httpContent, ProxyFilterRequestContentChain chain) {
                handleProxyData(clientChannel, httpContent);
            }

            @Override
            public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpResponse httpResponse, ProxyFilterResponseChain chain) {
                clientChannel.writeAndFlush(httpResponse);
            }

            @Override
            public void afterResponse(Channel clientChannel, Channel proxyChannel, HttpContent httpContent, ProxyFilterResponseContentChain chain) {
                clientChannel.writeAndFlush(httpContent);
            }
        };
    }

    private boolean isConnect(HttpMethod method) {
        return HttpMethod.CONNECT.equals(method);
    }
}
