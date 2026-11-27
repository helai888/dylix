#import <UIKit/UIKit.h>

static inline UIColor *DXDyn(UIColor *light, UIColor *dark) {
    return [UIColor colorWithDynamicProvider:^UIColor *(UITraitCollection *t){ return t.userInterfaceStyle==UIUserInterfaceStyleDark?dark:light; }];
}
static inline UIColor *DXHex(NSInteger lightHex, NSInteger darkHex) {
    UIColor *l=[UIColor colorWithRed:((lightHex>>16)&0xff)/255.0 green:((lightHex>>8)&0xff)/255.0 blue:(lightHex&0xff)/255.0 alpha:1];
    UIColor *d=[UIColor colorWithRed:((darkHex>>16)&0xff)/255.0 green:((darkHex>>8)&0xff)/255.0 blue:(darkHex&0xff)/255.0 alpha:1];
    return DXDyn(l,d);
}
static inline UIColor *DXBackgroundColor(void) { return DXHex(0xEDF0F7, 0x0D1017); }
static inline UIColor *DXSurfaceColor(void) { return DXHex(0xFFFFFF, 0x1B2130); }
static inline UIColor *DXSurfaceMutedColor(void) { return DXHex(0xE3E9F4, 0x252D40); }
static inline UIColor *DXBrandColor(void) { return DXHex(0x4B67B4, 0x8FA5DC); }
static inline UIColor *DXBrandPressedColor(void) { return DXHex(0x3D559A, 0x7E97D4); }
static inline UIColor *DXUserBubbleColor(void) { return DXHex(0xD9E4F8, 0x2A3A5F); }
static inline UIColor *DXLabelColor(void) { return DXHex(0x182136, 0xEDF0F7); }
static inline UIColor *DXSecondaryLabelColor(void) { return DXHex(0x67718C, 0x9AA5BE); }
static inline UIColor *DXSeparatorColor(void) { return DXHex(0xD8DEEB, 0x2C3448); }
static inline UIColor *DXCodeFillColor(void) { return DXHex(0xE7ECF6, 0x232B3E); }
static inline void DXApplyCardStyle(UIView *view, CGFloat radius) {
    view.backgroundColor=DXSurfaceColor();
    view.layer.cornerRadius=radius;
    view.layer.shadowColor=UIColor.blackColor.CGColor;
    view.layer.shadowOpacity=0.07;
    view.layer.shadowRadius=16;
    view.layer.shadowOffset=CGSizeMake(0,4);
    view.layer.masksToBounds=NO;
}
static inline void DXApplyPillStyle(UIView *view) {
    view.backgroundColor=DXSurfaceColor();
    view.layer.cornerRadius=22;
    view.layer.shadowColor=UIColor.blackColor.CGColor;
    view.layer.shadowOpacity=0.08;
    view.layer.shadowRadius=12;
    view.layer.shadowOffset=CGSizeMake(0,3);
    view.layer.masksToBounds=NO;
}
static inline void DXStyleTableAsCards(UITableView *table) {
    table.backgroundColor=DXBackgroundColor();
    table.separatorColor=DXSeparatorColor();
}
static inline void DXStyleNavBar(UINavigationBar *bar) {
    UINavigationBarAppearance *a=[UINavigationBarAppearance new];
    [a configureWithTransparentBackground];
    a.backgroundColor=DXBackgroundColor();
    a.shadowColor=UIColor.clearColor;
    a.titleTextAttributes=@{NSForegroundColorAttributeName:DXLabelColor()};
    a.largeTitleTextAttributes=@{NSForegroundColorAttributeName:DXLabelColor()};
    bar.standardAppearance=a;
    bar.scrollEdgeAppearance=a;
    bar.tintColor=DXBrandColor();
}
