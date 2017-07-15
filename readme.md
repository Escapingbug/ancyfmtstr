# ancyfmtstr
Simple script to make life easier when facing format string bug exploitation

# Usage
```
from ancyfmtstr import fmtstr
fmtstr.fmtstr_payload(6, writes)
```

This API is almost the same as the pwntools one, with the same name.

# Enhance?
The helper script from pwntools have several disadvantages:
It writes the address at the beginning of the payload, which is not good when you have read as read function.
Since you can write any address, but the printf use the beginning of your payload, you can't exploit that with that script.

And, is it too long? That what I thought for now.

I made some changes to the generation algorithm, I hope this one is better, but I am not for sure.
