Pod::Spec.new do |s|
  s.name             = 'SwiftCryptoPro'
  s.version          = '1.0.0'
  s.summary          = 'Cryptography framework for iOS with AES, RSA, and hashing'
  s.description      = 'Cryptography framework for iOS with AES, RSA, and hashing. Built with modern Swift.'
  s.homepage         = 'https://github.com/muhittincamdali/SwiftCrypto-Pro'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Muhittin Camdali' => 'contact@muhittincamdali.com' }
  s.source           = { :git => 'https://github.com/muhittincamdali/SwiftCrypto-Pro.git', :tag => s.version.to_s }
  s.ios.deployment_target = '15.0'
  s.swift_versions = ['5.9', '5.10', '6.0']
  s.source_files = 'Sources/**/*.swift'
end
