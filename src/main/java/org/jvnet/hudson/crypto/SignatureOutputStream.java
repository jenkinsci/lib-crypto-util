/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jvnet.hudson.crypto;

import edu.umd.cs.findbugs.annotations.NonNull;

import java.security.Signature;
import java.security.SignatureException;
import java.io.FilterOutputStream;
import java.io.OutputStream;
import java.io.IOException;

/**
 * @author Kohsuke Kawaguchi
 */
public class SignatureOutputStream extends FilterOutputStream {
    private final Signature sig;

    public SignatureOutputStream(OutputStream out, Signature sig) {
        super(out);
        this.sig = sig;
    }

    public SignatureOutputStream(Signature sig) {
        this(OutputStream.nullOutputStream(), sig);
    }

    @Override
    public void write(int b) throws IOException {
        try {
            sig.update((byte)b);
            out.write(b);
        } catch (SignatureException e) {
            throw new IOException(e);
        }
    }

    @Override
    public void write(@NonNull byte[] b, int off, int len) throws IOException {
        try {
            sig.update(b,off,len);
            out.write(b,off,len);
        } catch (SignatureException e) {
            throw new IOException(e);
        }
    }
}
