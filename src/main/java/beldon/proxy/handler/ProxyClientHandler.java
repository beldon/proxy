package beldon.proxy.handler;

import beldon.proxy.filter.chain.ProxyFilterChain;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.util.ReferenceCountUtil;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ProxyClientHandler extends ChannelInboundHandlerAdapter {

    private Channel clientChannel;
    private ProxyFilterChain filterChain;

    public ProxyClientHandler(Channel clientChannel, ProxyFilterChain filterChain) {
        this.clientChannel = clientChannel;
        this.filterChain = filterChain;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        //客户端channel已关闭则不转发了
        if (!clientChannel.isOpen()) {
            ReferenceCountUtil.release(msg);
            return;
        }
        if (msg instanceof HttpResponse) {
            Channel proxyChannel = ctx.channel();
            HttpResponse httpResponse = (HttpResponse) msg;
            filterChain.doFilter(clientChannel, ctx.channel(), httpResponse);
            if (isWebsocket(httpResponse)) {
                //websocket转发原始报文
                proxyChannel.pipeline().remove("httpCodec");
                clientChannel.pipeline().remove("httpCodec");
            }
        } else if (msg instanceof HttpContent) {
            HttpContent httpContent = (HttpContent) msg;
            filterChain.doFilter(clientChannel, ctx.channel(), httpContent);
        } else {
            clientChannel.writeAndFlush(msg);
        }
    }

    @Override
    public void channelUnregistered(ChannelHandlerContext ctx) throws Exception {
        ctx.channel().close();
        clientChannel.close();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        ctx.channel().close();
        clientChannel.close();
    }

    private boolean isWebsocket(HttpResponse httpResponse) {
        return HttpHeaderValues.WEBSOCKET.toString().equals(httpResponse.headers().get(HttpHeaderNames.UPGRADE));
    }
}
