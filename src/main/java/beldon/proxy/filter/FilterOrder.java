package beldon.proxy.filter;

/**
 * @author Beldon
 * @create 2018-07-12 11:35
 */
public interface FilterOrder {
    /**
     * 获取排序，越小越靠前，默认为0
     *
     * @return
     */
    int getFilterOrder();
}
