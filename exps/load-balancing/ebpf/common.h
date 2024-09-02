static __always_inline bool _pull_and_validate_data(struct __sk_buff *skb,
                                                    void **data_,
                                                    void **data_end_,
                                                    uint16_t size) {
    int err;
    void *data, *data_end;
    if (bpf_skb_pull_data(skb, size) < 0) {
        return false;
    }

    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;

    if (data + size > data_end) {
        bpf_printk("Unable to pull %d data from skb\n", size);
        return false;
    }

    *data_end_ = (void *)(long)skb->data_end;
    *data_ = (void *)(long)skb->data;

    return true;
}