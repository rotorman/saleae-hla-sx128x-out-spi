from enum import Enum
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame

class PacketType(Enum):
    GFSK = 0x00
    LORA = 0x01
    RANGING = 0x02
    FLRC = 0x03
    BLE = 0x04
    UNDEFINED = 0xFF

class sx128x_out(HighLevelAnalyzer):
    result_types = {
        "SpiTransaction": {
            "format": "{{data.dataout}}"
        },
        "SpiTransactionError": {
            "format": "ERROR: {{data.error_info}}",
        }
    }
    
    packetType: PacketType

    def __init__(self):
        # Holds the individual SPI result frames that make up the transaction
        self.frames = []

        # Whether SPI is currently enabled
        self.spi_enable = False
        
        # Wheater we are processing status bytes from SX128x
        self.statusBytes = True

        # Start time of the transaction - equivalent to the start time of the "Enable" frame
        self.transaction_start_time = None

        # Start time of the data transaction
        self.data_transaction_start_time = None

        # Whether there was an error.
        self.error = False
        
        # Initialize packetType to undefined
        self.packetType = PacketType.UNDEFINED

    def handle_enable(self, frame: AnalyzerFrame):
        self.frames = []
        self.spi_enable = True
        self.statusBytes = True
        self.error = False
        self.transaction_start_time = frame.start_time
        self.data_transaction_start_time = None

    def reset(self):
        self.frames = []
        self.spi_enable = False
        self.statusBytes = True
        self.error = False
        self.transaction_start_time = None
        self.data_transaction_start_time = None

    def is_valid_transaction(self) -> bool:
        return self.spi_enable and (not self.error) and (self.transaction_start_time is not None)

    def status_byte(self, status) -> str:
        M = (status & 0xE0) >> 5 # mode
        S = (status & 0x1C) >> 2 # status
        resM = "ERROR"
        if M == 0: resM = "Reserved"
        if M == 1: resM = "Reserved"
        if M == 2: resM = "STDBY_RC"
        if M == 3: resM = "STDBY_XOSC"
        if M == 4: resM = "FS"
        if M == 5: resM = "Rx"
        if M == 6: resM = "Tx"
        resS = "ERROR"
        if S == 0: resS = "Reserved"
        if S == 1: resS = "Done"
        if S == 2: resS = "DataAvailable"
        if S == 3: resS = "Timeout"
        if S == 4: resS = "ProcessErr"
        if S == 5: resS = "ExecErr"
        if S == 6: resS = "TxDone"
        return "Status:M=" + resM + ",S=" + resS

    def handle_result(self, frame):
        if self.spi_enable:
            self.frames.append(frame)

            miso = bytearray()
            mosi = bytearray()

            for frame in self.frames:
                miso += frame.data["miso"]
                mosi += frame.data["mosi"]

            if self.statusBytes:
                # Check if the communication is at a point where next data instead of status will be output
                
                # 0x03 = GetPacketType()
                if len(mosi) == 2 and len(miso) == 2 and mosi[0] == 0x03:
                    self.statusBytes = False

                # 0x15 = GetIrqStatus()
                if len(mosi) == 2 and len(miso) == 2 and mosi[0] == 0x15:
                    self.statusBytes = False

                # 0x17 = GetRxBufferStatus()
                if len(mosi) == 2 and len(miso) == 2 and mosi[0] == 0x17:
                    self.statusBytes = False

                # 0x19 = ReadRegister(address)
                if len(mosi) == 4 and len(miso) == 4 and mosi[0] == 0x19:
                    self.statusBytes = False

                # 0x1B = ReadBuffer(offset)
                if len(mosi) == 3 and len(miso) == 3 and mosi[0] == 0x1B:
                    self.statusBytes = False

                # 0x1D = GetPacketStatus()
                if len(mosi) == 2 and len(miso) == 2 and mosi[0] == 0x1D:
                    self.statusBytes = False
                    
                # 0x1F = GetRssiInst()
                if len(mosi) == 2 and len(miso) == 2 and mosi[0] == 0x1F:
                    self.statusBytes = False
                    
                return AnalyzerFrame(
                    "SpiTransaction",
                    frame.start_time,
                    frame.end_time,
                    { "dataout": self.status_byte(miso[len(miso)-1]) }
                )
            else:
                if self.data_transaction_start_time == None: self.data_transaction_start_time = frame.start_time

                # 0x03 = GetPacketType()
                if len(mosi) >= 3 and len(miso) >= 3 and mosi[0] == 0x03:
                    pType = "UNDEFINED"
                    if miso[2] == PacketType.GFSK:
                        pType = "GFSK"
                    if miso[2] == PacketType.LORA:
                        pType = "LORA"
                    if miso[2] == PacketType.RANGING:
                        pType = "RANGING"
                    if miso[2] == PacketType.FLRC:
                        pType = "FLRC"
                    if miso[2] == PacketType.BLE:
                        pType = "BLE"
                    return AnalyzerFrame(
                        "SpiTransaction",
                        self.data_transaction_start_time,
                        frame.end_time,
                        { "dataout": "GetPacketType()=" + pType }
                    )

                # 0x15 = GetIrqStatus()
                if len(mosi) >= 4 and len(miso) >= 4 and mosi[0] == 0x15:
                    irqStatus = miso[2]*256 + miso[3]
                    return AnalyzerFrame(
                        "SpiTransaction",
                        self.data_transaction_start_time,
                        frame.end_time,
                        { "dataout": "GetIrqStatus()=" + hex(irqStatus) }
                    )
                
                # 0x17 = GetRxBufferStatus()
                if len(mosi) >= 4 and len(miso) >= 4 and mosi[0] == 0x17:
                    rxPayloadLen = miso[2]
                    rxStartBufP = miso[3]
                    return AnalyzerFrame(
                        "SpiTransaction",
                        self.data_transaction_start_time,
                        frame.end_time,
                        { "dataout": "GetRxBufferStatus()=rxPayloadLen=" + str(rxPayloadLen) + ", rxStartBuffP=" + hex(rxStartBufP) }
                    )

                # 0x19 = ReadRegister(address)
                if len(mosi) >= 5 and len(miso) >= 5 and mosi[0] == 0x19:
                    address = (mosi[1]<<8)+mosi[2] + (len(miso) - 5)
                    value = miso[len(miso)-1]
                    return AnalyzerFrame(
                        "SpiTransaction",
                        #self.data_transaction_start_time,
                        frame.start_time,
                        frame.end_time,
                        { "dataout": "ReadRegister(@" + hex(address) + ")=" + hex(value) }
                    )
                    
                # 0x1B = ReadBuffer(offset)
                if len(mosi) >= 4 and len(miso) >= 4 and mosi[0] == 0x1B:
                    offset = mosi[1]
                    readbytes = hex(miso[3])
                    if len(miso) > 4:
                        for x in range(4, len(miso)):
                            readbytes += " " + hex(miso[x])
                    return AnalyzerFrame(
                        "SpiTransaction",
                        self.data_transaction_start_time,
                        frame.end_time,
                        { "dataout": "ReadBuffer(offset=" + hex(offset) + ")=" + readbytes}
                    )

                # 0x1D = GetPacketStatus()
                if len(mosi) >= 7 and len(miso) >= 7 and mosi[0] == 0x1D:
                    if self.packetType == PacketType.BLE or self.packetType == PacketType.GFSK or self.packetType == PacketType.FLRC:
                        if self.packetType == PacketType.BLE:
                            result = "BLE:"
                        if self.packetType == PacketType.GFSK:
                            result = "GFSK:"
                        if self.packetType == PacketType.FLRC:
                            result = "FLRC:"
                        result += "RFU=" + hex(miso[2])
                        result += ", rssiSync=" + str(-miso[3]/2) + " dBm"
                        result += ", errors=" + hex(miso[4])
                        result += ", status=" + hex(miso[5])
                        syncResult = "sync=ERROR"
                        if (miso[6] & 0x03) == 0: syncResult = ", SyncAddrDetection Error"
                        if (miso[6] & 0x03) == 1: syncResult = ", SyncAddr 1 detected"
                        if (miso[6] & 0x03) == 2: syncResult = ", SyncAddr 2 detected"
                        if (miso[6] & 0x03) == 3: syncResult = ", SyncAddr 3 detected"
                        result += ", " + syncResult
                        return AnalyzerFrame(
                            "SpiTransaction",
                            self.data_transaction_start_time,
                            frame.end_time,
                            { "dataout": "GetPacketStatus()=" + result }
                        )                        
                    if self.packetType == PacketType.LORA or self.packetType == PacketType.RANGING:
                        if self.packetType == PacketType.LORA:
                            result = "LORA:"
                        if self.packetType == PacketType.RANGING:
                            result = "RANGING:"
                        result += "rssiSync=" + str(-miso[2]/2) + " dBm"
                        result += ", snr=" + str(miso[3]/4) + " dB"
                        return AnalyzerFrame(
                            "SpiTransaction",
                            self.data_transaction_start_time,
                            frame.end_time,
                            { "dataout": "GetPacketStatus()=" + result }
                        )                        
                        
                    return AnalyzerFrame(
                        "SpiTransaction",
                        self.data_transaction_start_time,
                        frame.end_time,
                        { "dataout": "GetPacketStatus()=UNDEFINED protocol" }
                    )                        

                # 0x1F = GetRssiInst()
                if len(mosi) >= 3 and len(miso) >= 3 and mosi[0] == 0x1F:
                    return AnalyzerFrame(
                        "SpiTransaction",
                        self.data_transaction_start_time,
                        frame.end_time,
                        { "dataout": "GetRssiInst()=" + str(-miso[2]/2) + " dBm" }
                    )

    def handle_disable(self, frame):
        result = None
        
        miso = bytearray()
        mosi = bytearray()

        for frame in self.frames:
            miso += frame.data["miso"]
            mosi += frame.data["mosi"]
            
        # 0x03 = GetPacketType()
        if len(mosi) >= 3 and len(miso) >= 3 and mosi[0] == 0x03:
            found = False
            if miso[2] == PacketType.GFSK:
                self.packetType = PacketType.GFSK
                found = True
            if miso[2] == PacketType.LORA:
                self.packetType = PacketType.LORA
                found = True
            if miso[2] == PacketType.RANGING:
                self.packetType = PacketType.RANGING
                found = True
            if miso[2] == PacketType.FLRC:
                self.packetType = PacketType.FLRC
                found = True
            if miso[2] == PacketType.BLE:
                self.packetType = PacketType.BLE
                found = True
            if not found: self.packetType = PacketType.UNDEFINED


        # 0x8A = SetPacketType(packetType)
        if len(mosi) >= 2 and mosi[0] == 0x8A:
            found = False
            if mosi[1] == 0x00:
                self.packetType = PacketType.GFSK
                found = True
            if mosi[1] == 0x01:
                self.packetType = PacketType.LORA
                found = True
            if mosi[1] == 0x02:
                self.packetType = PacketType.RANGING
                found = True
            if mosi[1] == 0x03:
                self.packetType = PacketType.FLRC
                found = True
            if mosi[1] == 0x04:
                self.packetType = PacketType.BLE
                found = True
            if not found: self.packetType = PacketType.UNDEFINED
        
        if not self.is_valid_transaction():
            result = AnalyzerFrame(
                "SpiTransactionError",
                frame.start_time,
                frame.end_time,
                {
                    "error_info": "Invalid SPI transaction (spi_enable={}, error={}, transaction_start_time={})".format(
                        self.spi_enable,
                        self.error,
                        self.transaction_start_time,
                    )
                }
            )

        self.reset()
        if result != None: return result

    def handle_error(self, frame):
        result = AnalyzerFrame(
            "SpiTransactionError",
            frame.start_time,
            frame.end_time,
            {
                "error_info": "The clock was in the wrong state when the enable signal transitioned to active"
            }
        )
        self.reset()

    def decode(self, frame: AnalyzerFrame):
        if frame.type == "enable":
            return self.handle_enable(frame)
        elif frame.type == "result":
            return self.handle_result(frame)
        elif frame.type == "disable":
            return self.handle_disable(frame)
        elif frame.type == "error":
            return self.handle_error(frame)
        else:
            return AnalyzerFrame(
                "SpiTransactionError",
                frame.start_time,
                frame.end_time,
                {
                    "error_info": "Unexpected frame type from input analyzer: {}".format(frame.type)
                }
            )
