package beldon.proxy.config;

import beldon.proxy.filter.ProxyFilter;
import lombok.Data;

/**
 * @author Beldon
 * @create 2018-07-13 09:44
 */
@Data
public class ProxyFilterWrapper {
    private int order;
    private final ProxyFilter filter;

    public ProxyFilterWrapper(ProxyFilter filter) {
        this.filter = filter;
    }

    public ProxyFilterWrapper(ProxyFilter filter,int order) {
        this.filter = filter;
        this.order = order;
    }
}
