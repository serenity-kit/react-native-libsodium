// by https://github.com/jedisct1/libsodium.js/blob/abc0e40a95b8a2874533c626bd7d2a5aad5e65e5/wrapper/wrap-template.js#L215
// licensed under MIT, see LICENSE_Libsodiumjs
export const to_string = (bytes: Uint8Array): string => {
  if (typeof TextDecoder === 'function') {
    return new TextDecoder('utf-8', {
      fatal: true,
    }).decode(bytes);
  }

  var toStringChunkSize = 8192,
    numChunks = Math.ceil(bytes.length / toStringChunkSize);
  if (numChunks <= 1) {
    try {
      // @ts-ignore
      return decodeURIComponent(escape(String.fromCharCode.apply(null, bytes)));
    } catch {
      throw new TypeError('The encoded data was not valid.');
    }
  }
  var totalString = '';
  var sequenceReadOffset = 0;
  for (var i = 0; i < numChunks; i++) {
    var currentChunk = Array.prototype.slice.call(
      bytes,
      i * toStringChunkSize + sequenceReadOffset,
      (i + 1) * toStringChunkSize + sequenceReadOffset
    );
    //Depending on how much we have shifted
    // eslint-disable-next-line eqeqeq
    if (currentChunk.length == 0) {
      continue;
    }

    //Checking that we didn't cut the buffer in the middle of a UTF8 sequence.
    //If we did, remove the bytes of the "cut" sequence and
    //decrement sequenceReadOffset for each removed byte
    var sequenceDetectionComplete,
      sequenceIndex = currentChunk.length,
      sequenceLength = 0;

    //This loop will read the chunk from its end, looking for sequence start bytes
    do {
      sequenceIndex--;
      var currentByte = currentChunk[sequenceIndex];

      if (currentByte >= 240) {
        //Beginning of a 4-byte UTF-8 sequence
        sequenceLength = 4;
        sequenceDetectionComplete = true;
      } else if (currentByte >= 224) {
        //Beginning of a 3-byte UTF-8 sequence
        sequenceLength = 3;
        sequenceDetectionComplete = true;
      } else if (currentByte >= 192) {
        //Beginning of a 2-byte UTF-8 sequence
        sequenceLength = 2;
        sequenceDetectionComplete = true;
      } else if (currentByte < 128) {
        //A one byte UTF-8 char
        sequenceLength = 1;
        sequenceDetectionComplete = true;
      }
      //The values between [128, 192[ are part of a UTF-8 sequence.
      //The loop will not exit in that case, and will iterate one byte backwards instead
    } while (!sequenceDetectionComplete);

    var extraBytes = sequenceLength - (currentChunk.length - sequenceIndex);
    for (var j = 0; j < extraBytes; j++) {
      sequenceReadOffset--;
      currentChunk.pop();
    }

    // @ts-ignore
    totalString += to_string(currentChunk);
  }
  return totalString;
};

// licensed under MIT, see LICENSE_Libsodiumjs
export enum base64_variants {
  ORIGINAL = 1,
  ORIGINAL_NO_PADDING = 3,
  URLSAFE = 5,
  URLSAFE_NO_PADDING = 7,
}
