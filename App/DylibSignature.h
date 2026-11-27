#import <Foundation/Foundation.h>
#import <mach-o/loader.h>
#import <CommonCrypto/CommonDigest.h>

// Validate bundled LLD's thin ARM64 ad-hoc output, including every code page.
// File-integrity validation does not imply device trustcache admission.
static uint32_t TMCSigBE32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static BOOL TMCValidateDylibSignature(NSData *data, NSError **error) {
    NSString *(^problem)(void) = ^NSString *{
        if (data.length < sizeof(struct mach_header_64)) return @"动态库 Mach-O 头不完整";
        struct mach_header_64 h; memcpy(&h, data.bytes, sizeof(h));
        if (h.magic != MH_MAGIC_64 || h.cputype != CPU_TYPE_ARM64 || h.filetype != MH_DYLIB || h.sizeofcmds > data.length-sizeof(h) || h.ncmds > h.sizeofcmds/8) return @"动态库 Mach-O 头无效";
        const uint8_t *bytes = data.bytes;
        NSUInteger offset=sizeof(h), end=offset+h.sizeofcmds, signatures=0;
        struct linkedit_data_command sig={0};
        for (uint32_t i=0;i<h.ncmds;i++) {
            if (offset>end || end-offset<sizeof(struct load_command)) return @"动态库加载命令被截断";
            struct load_command c; memcpy(&c,bytes+offset,sizeof(c));
            if (c.cmdsize<8 || c.cmdsize%8 || c.cmdsize>end-offset) return @"动态库加载命令长度无效";
            if (c.cmd==LC_CODE_SIGNATURE) {
                if (++signatures!=1 || c.cmdsize!=sizeof(sig)) return @"动态库签名命令重复或无效";
                memcpy(&sig,bytes+offset,sizeof(sig));
            }
            offset+=c.cmdsize;
        }
        if (offset!=end) return @"动态库加载命令数量不一致";
        if (!signatures) return @"动态库缺少 ad-hoc 签名，已停止导出和打包";
        if (sig.dataoff<end || sig.dataoff>data.length || sig.datasize<12 || sig.datasize>data.length-sig.dataoff) return @"动态库签名范围无效";
        const uint8_t *blob=bytes+sig.dataoff;
        uint32_t length=TMCSigBE32(blob+4), count=TMCSigBE32(blob+8);
        if (TMCSigBE32(blob)!=0xfade0cc0 || length<12 || length>sig.datasize || count>(length-12)/8) return @"动态库签名 SuperBlob 无效";
        NSUInteger primary=0, directories=0;
        for (uint32_t i=0;i<count;i++) {
            uint32_t slot=TMCSigBE32(blob+12+i*8), start=TMCSigBE32(blob+16+i*8);
            if (start<12+(uint64_t)count*8 || start>length || length-start<8) return @"动态库签名子块偏移无效";
            const uint8_t *cd=blob+start;
            uint32_t size=TMCSigBE32(cd+4);
            if (size<8 || size>length-start) return @"动态库签名子块被截断";
            if (slot!=0 && !(slot>=0x1000 && slot<=0x1005)) continue;
            if (slot==0 && ++primary!=1) return @"动态库主 CodeDirectory 重复";
            directories++;
            if (size<44 || TMCSigBE32(cd)!=0xfade0c02) return @"动态库 CodeDirectory 无效";
            uint32_t version=TMCSigBE32(cd+8), flags=TMCSigBE32(cd+12), hashOffset=TMCSigBE32(cd+16), special=TMCSigBE32(cd+24), slots=TMCSigBE32(cd+28);
            uint64_t limit=TMCSigBE32(cd+32);
            if (!(flags&2) || version<0x20001 || version>0x20600) return @"动态库不是受支持的 ad-hoc 签名";
            if (version>=0x20100 && (size<48 || TMCSigBE32(cd+44))) return @"动态库签名包含不支持的 scatter 布局";
            if (version>=0x20300) {
                if (size<64) return @"动态库扩展 CodeDirectory 被截断";
                uint64_t large=((uint64_t)TMCSigBE32(cd+56)<<32)|TMCSigBE32(cd+60);
                if (large) limit=large;
            }
            if (cd[36]!=CC_SHA256_DIGEST_LENGTH || cd[37]!=2 || !cd[39] || cd[39]>20) return @"动态库签名哈希算法或页大小不受支持";
            uint64_t page=1ULL<<cd[39];
            if (limit!=sig.dataoff || slots!=(limit+page-1)/page || hashOffset<44 || hashOffset>size || (uint64_t)special*32>hashOffset-44 || (uint64_t)slots*32>size-hashOffset) return @"动态库签名覆盖范围或哈希表无效";
            for (uint32_t n=0;n<slots;n++) {
                uint64_t begin=(uint64_t)n*page;
                unsigned char digest[CC_SHA256_DIGEST_LENGTH];
                CC_SHA256(bytes+begin,(CC_LONG)MIN(page,limit-begin),digest);
                if (memcmp(digest,cd+hashOffset+(NSUInteger)n*32,32)) return @"动态库签名页哈希不匹配，文件可能在签名后被修改";
            }
        }
        if (primary!=1 || !directories) return @"动态库缺少主 CodeDirectory";
        return nil;
    };
    NSString *message=problem();
    if (message && error) *error=[NSError errorWithDomain:@"Dylix.Signature" code:1 userInfo:@{NSLocalizedDescriptionKey:message}];
    return message==nil;
}
static BOOL TMCFixDataConstReadOnly(NSMutableData *data) {
    if (data.length < sizeof(struct mach_header_64)) return NO;
    struct mach_header_64 h; memcpy(&h, data.bytes, sizeof(h));
    if (h.magic != MH_MAGIC_64 || h.sizeofcmds > data.length-sizeof(h)) return NO;
    const uint8_t *bytes = data.bytes;
    NSUInteger offset=sizeof(h), end=offset+h.sizeofcmds, flagsOffset=0;
    struct linkedit_data_command sig={0}; BOOL found=NO, already=NO, hasSig=NO;
    for (uint32_t i=0;i<h.ncmds;i++) {
        if (offset>end || end-offset<sizeof(struct load_command)) return NO;
        struct load_command c; memcpy(&c,bytes+offset,sizeof(c));
        if (c.cmdsize<8 || c.cmdsize>end-offset) return NO;
        if (c.cmd==LC_SEGMENT_64 && c.cmdsize>=sizeof(struct segment_command_64)) {
            struct segment_command_64 s; memcpy(&s,bytes+offset,sizeof(s));
            if (!strncmp(s.segname,"__DATA_CONST",sizeof(s.segname))) { found=YES; already=(s.flags&SG_READ_ONLY)!=0; flagsOffset=offset+offsetof(struct segment_command_64,flags); }
        }
        if (c.cmd==LC_CODE_SIGNATURE && c.cmdsize>=sizeof(sig)) { memcpy(&sig,bytes+offset,sizeof(sig)); hasSig=YES; }
        offset+=c.cmdsize;
    }
    if (!found || already || !flagsOffset) return NO;
    uint32_t flags; memcpy(&flags,bytes+flagsOffset,sizeof(flags)); flags|=SG_READ_ONLY;
    memcpy(data.mutableBytes+flagsOffset,&flags,sizeof(flags));
    if (hasSig && sig.dataoff>0 && sig.dataoff<data.length && sig.datasize>=12 && sig.datasize<=data.length-sig.dataoff) {
        const uint8_t *blob=bytes+sig.dataoff;
        uint32_t count=TMCSigBE32(blob+8);
        if (TMCSigBE32(blob)==0xfade0cc0 && count<=(TMCSigBE32(blob+4)-12)/8) {
            for (uint32_t i=0;i<count;i++) {
                uint32_t slot=TMCSigBE32(blob+12+i*8), start=TMCSigBE32(blob+16+i*8);
                if (slot!=0 && !(slot>=0x1000 && slot<=0x1005)) continue;
                if (start>sig.datasize || sig.datasize-start<64) continue;
                const uint8_t *cd=blob+start;
                if (TMCSigBE32(cd)!=0xfade0c02) continue;
                uint32_t version=TMCSigBE32(cd+8), hashOffset=TMCSigBE32(cd+16), slots=TMCSigBE32(cd+28);
                uint64_t limit=TMCSigBE32(cd+32);
                if (version>=0x20300) { uint64_t large=((uint64_t)TMCSigBE32(cd+56)<<32)|TMCSigBE32(cd+60); if (large) limit=large; }
                uint8_t hashSize=cd[36], hashType=cd[37], pageLog=cd[39];
                if (!hashSize || hashSize>64 || !pageLog || pageLog>30) continue;
                uint64_t page=1ULL<<pageLog, pageIndex=flagsOffset/page;
                if (pageIndex>=slots) continue;
                uint64_t begin=pageIndex*page, span=limit>begin?MIN(page,limit-begin):0;
                unsigned char digest[64]; BOOL ok=YES;
                if (hashType==1) CC_SHA1(bytes+begin,(CC_LONG)span,digest);
                else if (hashType==2) CC_SHA256(bytes+begin,(CC_LONG)span,digest);
                else if (hashType==3) CC_SHA384(bytes+begin,(CC_LONG)span,digest);
                else if (hashType==4) CC_SHA512(bytes+begin,(CC_LONG)span,digest);
                else ok=NO;
                if (ok) memcpy(data.mutableBytes+sig.dataoff+start+hashOffset+pageIndex*hashSize,digest,MIN(hashSize,(uint8_t)sizeof(digest)));
            }
        }
    }
    return YES;
}
