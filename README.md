# Misery Node

My first plugin, not the easy choice, not the most beautiful and coded but dealing with memory and injection is an absolute mess for a first project ! 

- This plugin is an attempt to patch the MAX_NODES limit, cause request are mostly ignored since 4 years now. 
- It's stable as far as we tested.
- I'll update it each time when it will be needed due to gmod update or personnal update, feel free to contribute. 



# Installation

- Put the misery_node_win64.dll inside gmodds/bin/win64.
- then go into your cfg and open autoexec.cfg and type this.

```
plugin_load "misery_node_win64"
ai_norebuildgraph 1
 ```

As you guessed this plugin is only working on 64 bits and windows for now. 
I'll add linux support maybe one day when i'll rework the patch system.

Thanks to [RaphaelIT7](https://github.com/RaphaelIT7/), his work is absolutely amazing and really helpful for learn. 
Thanks to the gmod community who helped me to deal with some bug.

