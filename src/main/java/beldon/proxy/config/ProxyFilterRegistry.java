package beldon.proxy.config;


import beldon.proxy.filter.FilterOrder;
import beldon.proxy.filter.ProxyFilter;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Beldon
 * @create 2018-07-12 12:22
 */
public class ProxyFilterRegistry {

    private List<ProxyFilterWrapper> proxyFilterWrappers = new ArrayList<>();

    private boolean doneSort;


    public void add(ProxyFilter filter) {
        if (filter instanceof FilterOrder) {
            proxyFilterWrappers.add(new ProxyFilterWrapper(filter, ((FilterOrder) filter).getFilterOrder()));
        } else {
            proxyFilterWrappers.add(new ProxyFilterWrapper(filter));
        }
    }

    public List<ProxyFilterWrapper> getProxyFilterWrappers() {
        if (!doneSort) {
            sort();
            doneSort = true;
        }
        return proxyFilterWrappers;
    }

    private void sort() {
        proxyFilterWrappers = proxyFilterWrappers.stream()
                .sorted(Comparator.comparing(ProxyFilterWrapper::getOrder))
                .collect(Collectors.toList());
    }
}
