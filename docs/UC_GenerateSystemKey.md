# UC Generate SystemKey

```flowchart
st=>start: Start
end=>end: End
error=>end: Error
input=>inputoutput: Key
choose_methods=>operation: As there are 6 system information sources
    1. Path/FileName (depend on target) 
    2. CPU(s) (Name, Vendor_Id, Brand, Frequency
    3. System (Name, HostName, Disks, CPU Count)
    4. User (Id, Name)
    5. Network(s) (MacAddr)
    6. Date of Creation (depend on target)
there are at least 10 possible information tags
info_tag_index=>operation: TagEnumerator = For each information tag available 
matching system information tags
ByteEnumerator = For each byte in input Key 
cond_chosen=>condition: Is there 3 tags chosen?
cond_tag=>condition: There are more Tags?
cond_bytes=>condition: There are more Bytes?
op_eval_byte_tag=>operation: With Byte and Tag
cond_can_get_tag=>condition: byte % 1 == 1
op_get_tag=>operation: Add Info Tag To Process
op_incr=>operation: Next InfoTag and Next Byte
op_gen=>operation: SystemKey = Use SHA3-256
Hash(InfoTag1Value XOR InfoTag2Value XOR InfoTag3Value)
ret=>inputoutput: Return SystemKey

st->input->choose_methods->info_tag_index->cond_chosen
cond_chosen(no)->cond_tag
cond_tag(no)->error
cond_tag(yes)->cond_bytes
cond_bytes(no)->error
cond_bytes(yes)->op_eval_byte_tag->cond_can_get_tag
cond_can_get_tag(yes)->op_get_tag(left)->cond_chosen
cond_can_get_tag(no)->op_incr(right)->cond_chosen
cond_chosen(yes)->op_gen->ret->end
```
