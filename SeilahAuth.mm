// SeilahAuth.mm — offline key validation, walang server needed
// Compile flags: -fobjc-arc -framework UIKit -framework Foundation -framework Security

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

// ── PALITAN NG SAME SECRET SA KEYGEN.PY ──────────────────────────────────
static const char kSecret[] = "SeilahRosXDJA_2024_ChangeThis!!";

static NSString * const kKeychainSvc = @"com.seilah.rosauthhook";
static NSString * const kKeychainKey = @"saved_key";

typedef void (^SeilahAuthCompletion)(BOOL ok);

// ── Helpers ───────────────────────────────────────────────────────────────

static NSData *_b32decode(NSString *str) {
    // Tanggalin ang "SEILAH-" prefix at dashes
    NSString *clean = [str uppercaseString];
    clean = [clean stringByReplacingOccurrencesOfString:@"SEILAH-" withString:@""];
    clean = [clean stringByReplacingOccurrencesOfString:@"-" withString:@""];

    // Pad to multiple of 8
    NSMutableString *padded = [clean mutableCopy];
    while (padded.length % 8 != 0) [padded appendString:@"="];

    // Base32 alphabet: A-Z = 0-25, 2-7 = 26-31
    NSString *alpha = @"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    NSMutableData *result = [NSMutableData data];
    NSUInteger len = padded.length;

    for (NSUInteger i = 0; i < len; i += 8) {
        uint64_t buf = 0;
        int valid = 0;
        for (int j = 0; j < 8; j++) {
            unichar c = [padded characterAtIndex:i + j];
            if (c == '=') break;
            NSRange r = [alpha rangeOfString:[NSString stringWithCharacters:&c length:1]];
            if (r.location == NSNotFound) return nil;
            buf = (buf << 5) | r.location;
            valid++;
        }
        int bytes = (valid * 5) / 8;
        for (int j = bytes - 1; j >= 0; j--) {
            uint8_t byte = (buf >> (j * 8)) & 0xFF;
            [result appendBytes:&byte length:1];
        }
    }
    return result;
}

static BOOL _validateKey(NSString *keyStr) {
    NSData *raw = _b32decode(keyStr);
    if (!raw || raw.length < 11) return NO; // rand_id(4) + ":" + expiry(≥1) + sig(6)

    // Huwag kasama yung huli 6 bytes (signature)
    NSData *data  = [raw subdataWithRange:NSMakeRange(0, raw.length - 6)];
    NSData *sig   = [raw subdataWithRange:NSMakeRange(raw.length - 6, 6)];

    // Verify HMAC
    uint8_t expected[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256,
           kSecret, strlen(kSecret),
           data.bytes, data.length,
           expected);

    // Compare unang 6 bytes ng HMAC sa sig
    if (memcmp(expected, sig.bytes, 6) != 0) return NO; // invalid key

    // Parse expiry mula sa data: format = "XXXXXXXX:1234567890"
    NSString *dataStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSArray *parts = [dataStr componentsSeparatedByString:@":"];
    if (parts.count < 2) return NO;

    NSTimeInterval expiry = [parts[1] doubleValue];
    if ([NSDate date].timeIntervalSince1970 > expiry) return NO; // expired na

    return YES;
}

// ── Keychain save/load ────────────────────────────────────────────────────

static void _saveKey(NSString *key) {
    NSDictionary *del = @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainSvc,
        (__bridge id)kSecAttrAccount: kKeychainKey,
    };
    SecItemDelete((__bridge CFDictionaryRef)del);

    NSData *data = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *add = @{
        (__bridge id)kSecClass:          (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService:    kKeychainSvc,
        (__bridge id)kSecAttrAccount:    kKeychainKey,
        (__bridge id)kSecValueData:      data,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock,
    };
    SecItemAdd((__bridge CFDictionaryRef)add, NULL);
}

static NSString *_loadKey(void) {
    NSDictionary *q = @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainSvc,
        (__bridge id)kSecAttrAccount: kKeychainKey,
        (__bridge id)kSecReturnData:  @YES,
        (__bridge id)kSecMatchLimit:  (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef result = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &result) != errSecSuccess)
        return nil;
    return [[NSString alloc] initWithData:(__bridge_transfer NSData *)result
                                 encoding:NSUTF8StringEncoding];
}

// ── Login ViewController ──────────────────────────────────────────────────

@interface SeilahLoginVC : UIViewController <UITextFieldDelegate>
@property (nonatomic, copy) SeilahAuthCompletion completion;
@end

@implementation SeilahLoginVC {
    UITextField *_keyField;
    UILabel     *_statusLabel;
    UIButton    *_loginBtn;
}

- (void)viewDidLoad {
    [super viewDidLoad];

    // Background
    UIBlurEffect *blur = [UIBlurEffect effectWithStyle:UIBlurEffectStyleDark];
    UIVisualEffectView *bg = [[UIVisualEffectView alloc] initWithEffect:blur];
    bg.frame = self.view.bounds;
    bg.autoresizingMask = 63;
    [self.view addSubview:bg];

    // Card
    UIView *card = [[UIView alloc] init];
    card.backgroundColor = [UIColor colorWithRed:0.06 green:0.06 blue:0.09 alpha:0.97];
    card.layer.cornerRadius = 18;
    card.layer.borderColor = [UIColor colorWithRed:0 green:0.8 blue:1 alpha:0.6].CGColor;
    card.layer.borderWidth = 1;
    card.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:card];

    // Title
    UILabel *title = [[UILabel alloc] init];
    title.text = @"SEILAH";
    title.textColor = [UIColor colorWithRed:0 green:0.85 blue:1 alpha:1];
    title.font = [UIFont boldSystemFontOfSize:28];
    title.textAlignment = NSTextAlignmentCenter;
    title.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:title];

    // Subtitle
    UILabel *sub = [[UILabel alloc] init];
    sub.text = @"I-enter ang license key mo";
    sub.textColor = [UIColor colorWithWhite:0.5 alpha:1];
    sub.font = [UIFont systemFontOfSize:11];
    sub.textAlignment = NSTextAlignmentCenter;
    sub.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:sub];

    // Text field
    _keyField = [[UITextField alloc] init];
    _keyField.attributedPlaceholder = [[NSAttributedString alloc]
        initWithString:@"SEILAH-XXXX-XXXX-XXXX"
            attributes:@{ NSForegroundColorAttributeName:
                [UIColor colorWithWhite:0.3 alpha:1] }];
    _keyField.textColor = UIColor.whiteColor;
    _keyField.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    _keyField.backgroundColor = [UIColor colorWithWhite:0.13 alpha:1];
    _keyField.layer.cornerRadius = 10;
    _keyField.textAlignment = NSTextAlignmentCenter;
    _keyField.autocorrectionType = UITextAutocorrectionTypeNo;
    _keyField.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    _keyField.returnKeyType = UIReturnKeyGo;
    _keyField.delegate = self;
    UIView *p1 = [[UIView alloc] initWithFrame:CGRectMake(0,0,10,0)];
    UIView *p2 = [[UIView alloc] initWithFrame:CGRectMake(0,0,10,0)];
    _keyField.leftView = p1; _keyField.leftViewMode = UITextFieldViewModeAlways;
    _keyField.rightView = p2; _keyField.rightViewMode = UITextFieldViewModeAlways;
    _keyField.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:_keyField];

    // Status
    _statusLabel = [[UILabel alloc] init];
    _statusLabel.text = @"";
    _statusLabel.font = [UIFont systemFontOfSize:11];
    _statusLabel.textColor = [UIColor colorWithRed:1 green:0.3 blue:0.3 alpha:1];
    _statusLabel.textAlignment = NSTextAlignmentCenter;
    _statusLabel.numberOfLines = 2;
    _statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [card addSubview:_statusLabel];

    // Button
    _loginBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    [_loginBtn setTitle:@"ACTIVATE" forState:UIControlStateNormal];
    _loginBtn.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    [_loginBtn setTitleColor:UIColor.blackColor forState:UIControlStateNormal];
    _loginBtn.backgroundColor = [UIColor colorWithRed:0 green:0.85 blue:1 alpha:1];
    _loginBtn.layer.cornerRadius = 10;
    _loginBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [_loginBtn addTarget:self action:@selector(_activate)
        forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:_loginBtn];

    // Constraints
    [NSLayoutConstraint activateConstraints:@[
        [card.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [card.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [card.widthAnchor constraintEqualToConstant:290],

        [title.topAnchor constraintEqualToAnchor:card.topAnchor constant:26],
        [title.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [title.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],

        [sub.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:4],
        [sub.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [sub.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],

        [_keyField.topAnchor constraintEqualToAnchor:sub.bottomAnchor constant:18],
        [_keyField.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [_keyField.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],
        [_keyField.heightAnchor constraintEqualToConstant:44],

        [_statusLabel.topAnchor constraintEqualToAnchor:_keyField.bottomAnchor constant:8],
        [_statusLabel.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [_statusLabel.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],
        [_statusLabel.heightAnchor constraintGreaterThanOrEqualToConstant:14],

        [_loginBtn.topAnchor constraintEqualToAnchor:_statusLabel.bottomAnchor constant:10],
        [_loginBtn.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:16],
        [_loginBtn.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-16],
        [_loginBtn.heightAnchor constraintEqualToConstant:46],
        [_loginBtn.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-26],
    ]];
}

- (BOOL)textFieldShouldReturn:(UITextField *)tf {
    [self _activate]; return YES;
}

- (void)_activate {
    NSString *key = [_keyField.text
        stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];

    if (key.length < 10) {
        _statusLabel.text = @"Key masyadong maikli.";
        return;
    }

    if (_validateKey(key)) {
        _saveKey(key);
        _statusLabel.textColor = [UIColor colorWithRed:0.2 green:1 blue:0.4 alpha:1];
        _statusLabel.text = @"✓ Na-activate na!";
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.7 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if (self.completion) self.completion(YES);
        });
    } else {
        _statusLabel.textColor = [UIColor colorWithRed:1 green:0.3 blue:0.3 alpha:1];
        _statusLabel.text = @"Invalid o expired na ang key.";
    }
}

@end

// ── Auth Manager ──────────────────────────────────────────────────────────

@interface SeilahAuthManager : NSObject
+ (instancetype)shared;
- (void)presentLoginIfNeededWithCompletion:(SeilahAuthCompletion)completion;
@end

@implementation SeilahAuthManager {
    UIWindow *_win;
}

+ (instancetype)shared {
    static SeilahAuthManager *s;
    static dispatch_once_t t;
    dispatch_once(&t, ^{ s = [self new]; });
    return s;
}

- (void)presentLoginIfNeededWithCompletion:(SeilahAuthCompletion)completion {
    // May saved key na ba?
    NSString *saved = _loadKey();
    if (saved && _validateKey(saved)) {
        if (completion) completion(YES);
        return;
    }
    dispatch_async(dispatch_get_main_queue(), ^{
        [self _showUI:completion];
    });
}

- (void)_showUI:(SeilahAuthCompletion)completion {
    UIWindowScene *scene = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if ([s isKindOfClass:UIWindowScene.class] &&
            s.activationState == UISceneActivationStateForegroundActive) {
            scene = (UIWindowScene *)s; break;
        }
    }
    if (!scene) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self _showUI:completion]; });
        return;
    }

    _win = [[UIWindow alloc] initWithWindowScene:scene];
    _win.windowLevel = UIWindowLevelAlert + 10;

    SeilahLoginVC *vc = [SeilahLoginVC new];
    __weak typeof(self) w = self;
    vc.completion = ^(BOOL ok) {
        w->_win.hidden = YES;
        w->_win = nil;
        if (completion) completion(ok);
    };
    vc.modalPresentationStyle = UIModalPresentationOverFullScreen;
    _win.rootViewController = vc;
    [_win makeKeyAndVisible];
}

@end

// ── Entry point ───────────────────────────────────────────────────────────

__attribute__((constructor))
static void SeilahInit(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [[SeilahAuthManager shared]
            presentLoginIfNeededWithCompletion:^(BOOL ok) {
                if (!ok) return;
                NSLog(@"[seilah] authenticated — go");
                // Dito ilagay ang feature enable calls mo pag ready
            }];
    });
}
