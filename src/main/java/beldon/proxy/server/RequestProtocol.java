package beldon.proxy.server;

import io.netty.handler.codec.http.HttpMethod;
import lombok.Data;

@Data
public class RequestProtocol {
    private String host;
    private HttpMethod method;
    private int port;
    private boolean ssl;
}
