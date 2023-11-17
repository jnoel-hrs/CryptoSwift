////  CryptoSwift
//
//  Copyright (C) 2014-__YEAR__ Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  In no event will the authors be held liable for any damages arising from the use of this software.
//
//  Permission is granted to anyone to use this software for any purpose,including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
//
//  - The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation is required.
//  - Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
//  - This notice may not be removed or altered from any source or binary distribution.
//

import Foundation
import XCTest
@testable import CryptoSwift

final class AESEncryptedFileTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() throws {
      let password = "supersecret"
      let plainText = "The quick brown fox jumps over the lazy dog"
      let cachesDirectory = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first!
      let cipherFilePath = cachesDirectory.appendingPathComponent("cipher-test.xlog")
      let bytesToWrite = plainText.bytes
      
      let encryptedFile = try AESEncryptedFile(cipherFilePath, password: password)
      let outputStream = try encryptedFile.openOutputStream()
      
      outputStream.write(bytesToWrite, maxLength: bytesToWrite.count)
      outputStream.close()
      
      let inputStream = try encryptedFile.openInputStream()
      let readBlockSize = 1024
      var inputBuffer = [UInt8](repeating: 0, count: readBlockSize)
      let readCount = inputStream.read(&inputBuffer, maxLength: 48)
      let readText = String(bytes: inputBuffer[0..<readCount], encoding: .utf8)!
      
      XCTAssertEqual(readText, plainText)
    }
}
